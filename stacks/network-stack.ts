import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

interface NetworkStackProps extends cdk.StackProps {
    /**
     * The number of firewall endpoints (and NAT gateways) to create.
     *
     * @default 1
     */
    readonly endpointCount?: number;

    /**
     * Mapping between VPC CIDR ranges and FQDNs to allowlist.
     */
    readonly cidrFqdns: { [name: string]: { cidrs: string[]; fqdns: string[] } };
}

export class NetworkStack extends cdk.Stack {
    private _transitGateway;

    constructor(scope: Construct, id: string, props: NetworkStackProps) {
        super(scope, id, props);

        if (cdk.Token.isUnresolved(this.account) || cdk.Token.isUnresolved(this.region)) {
            throw new Error('Stack account and region must be set');
        }

        // Create a VPC without any gateways to avoid CDK default routing, and subnets for each purpose in each AZ
        const vpc = new cdk.aws_ec2.Vpc(this, 'NetworkVpc', {
            createInternetGateway: false,
            natGateways: 0,
            subnetConfiguration: [
                { name: 'firewall', subnetType: cdk.aws_ec2.SubnetType.PRIVATE_ISOLATED },
                { name: 'nat', subnetType: cdk.aws_ec2.SubnetType.PRIVATE_ISOLATED },
                { cidrMask: 28, name: 'transit', subnetType: cdk.aws_ec2.SubnetType.PRIVATE_ISOLATED },
            ],
        });

        // Store the subnets that will hold firewall endpoints, may not include all firewall subnets
        const subnetsWithEndpoints = vpc
            .selectSubnets({ subnetGroupName: 'firewall' })
            .subnets.slice(0, props.endpointCount ?? 1);

        // Store the subnets that will hold NAT gateways, may not include all NAT subnets. Use the same AZs as the firewall endpoints
        const subnetsWithGateways = vpc.selectSubnets({
            subnetGroupName: 'nat',
            availabilityZones: subnetsWithEndpoints.map(({ availabilityZone }) => availabilityZone),
        }).subnets;

        // Create NAT gateways
        const natGateways = subnetsWithGateways.map(
            ({ subnetId }, i) =>
                new cdk.aws_ec2.CfnNatGateway(this, `NatGateway_${i + 1}`, {
                    subnetId,
                    allocationId: new cdk.aws_ec2.CfnEIP(this, `EIP_${i + 1}`, { domain: 'vpc' }).attrAllocationId,
                }),
        );

        // Create internet gateway
        const internetGateway = new cdk.aws_ec2.CfnInternetGateway(this, 'InternetGateway');

        // Attach the internet gateway to the VPC
        new cdk.aws_ec2.CfnVPCGatewayAttachment(this, 'InternetGatewayAttachment', {
            internetGatewayId: internetGateway.attrInternetGatewayId,
            vpcId: vpc.vpcId,
        });

        // Define stateful rules for each mapping of CIDRs and FQDNs to allowlist
        const statefulRules = Object.entries(props.cidrFqdns).map(
            ([ruleName, { cidrs, fqdns }]) =>
                new cdk.aws_networkfirewall.CfnRuleGroup(this, `${ruleName}AllowList`, {
                    capacity: 30000 / 20,
                    ruleGroupName: `${ruleName}AllowList`,
                    type: 'STATEFUL',
                    ruleGroup: {
                        ruleVariables: { ipSets: { HOME_NET: { definition: cidrs } } },
                        rulesSource: {
                            rulesSourceList: {
                                generatedRulesType: 'ALLOWLIST',
                                targets: fqdns,
                                targetTypes: ['HTTP_HOST', 'TLS_SNI'],
                            },
                        },
                    },
                }),
        );

        // Define a firewall policy
        const firewallPolicy = new cdk.aws_networkfirewall.CfnFirewallPolicy(this, 'FirewallPolicy', {
            firewallPolicy: {
                statefulRuleGroupReferences: statefulRules.map(({ attrRuleGroupArn }) => ({
                    resourceArn: attrRuleGroupArn,
                })),
                statelessDefaultActions: ['aws:forward_to_sfe'],
                statelessFragmentDefaultActions: ['aws:forward_to_sfe'],
            },
            firewallPolicyName: 'FirewallPolicy',
        });

        // Create the firewall
        const firewall = new cdk.aws_networkfirewall.CfnFirewall(this, 'Firewall', {
            firewallName: 'Firewall',
            firewallPolicyArn: firewallPolicy.attrFirewallPolicyArn,
            subnetMappings: subnetsWithEndpoints.map(({ subnetId }) => ({ subnetId })),
            vpcId: vpc.vpcId,
        });

        // The attribute returned by CFN is very hard to work with, map it out to each endpoint AZ with CFN functions
        const firewallEndpointIds = this.retrieveFirewallEndpointIds(
            firewall.attrEndpointIds,
            subnetsWithEndpoints.map(({ availabilityZone }) => availabilityZone),
        );

        // Setup logging for the firewall
        const logGroup = new cdk.aws_logs.LogGroup(this, 'FirewallLogGroup', {
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        });
        new cdk.aws_networkfirewall.CfnLoggingConfiguration(this, 'FirewallLogging', {
            firewallArn: firewall.attrFirewallArn,
            loggingConfiguration: {
                logDestinationConfigs: [
                    {
                        logDestination: { logGroup: logGroup.logGroupName },
                        logDestinationType: 'CloudWatchLogs',
                        logType: 'FLOW',
                    },
                ],
            },
        });

        // Create a transit gateway
        this._transitGateway = new cdk.aws_ec2.CfnTransitGateway(this, 'TransitGateway');

        // Attach the VPC to the transit gateway. Enable appliance mode to avoid cross AZ return traffic
        const attachment = new cdk.aws_ec2.CfnTransitGatewayAttachment(this, 'TransitGatewayAttachment', {
            options: { ApplianceModeSupport: 'enable' },
            subnetIds: vpc.selectSubnets({ subnetGroupName: 'transit' }).subnetIds,
            transitGatewayId: this._transitGateway.attrId,
            vpcId: vpc.vpcId,
        });

        // Create a log group for the custom resource so that it can be destroyed on stack termination
        const getRouteTableIdLogGroup = new cdk.aws_logs.LogGroup(this, 'GetRouteTableIdLogGroup', {
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        });

        // Retrieve the id of the route table created by the transit gateway
        const routeTableId = new cdk.custom_resources.AwsCustomResource(this, 'GetRouteTableId', {
            installLatestAwsSdk: false,
            logGroup: getRouteTableIdLogGroup,
            onUpdate: {
                action: 'describeTransitGateways',
                parameters: { TransitGatewayIds: [this._transitGateway.attrId] },
                physicalResourceId: cdk.custom_resources.PhysicalResourceId.of('GetRouteTableId'),
                service: 'EC2',
            },
            policy: cdk.custom_resources.AwsCustomResourcePolicy.fromSdkCalls({
                resources: cdk.custom_resources.AwsCustomResourcePolicy.ANY_RESOURCE,
            }),
        }).getResponseField('TransitGateways.0.Options.AssociationDefaultRouteTableId');

        // Outbound traffic routing

        // Create routes from the transit gateway to the network VPC attachment - depend on the attachment
        new cdk.aws_ec2.CfnTransitGatewayRoute(this, 'TransitGatewayRoute', {
            destinationCidrBlock: '0.0.0.0/0',
            transitGatewayAttachmentId: attachment.attrId,
            transitGatewayRouteTableId: routeTableId,
        }).node.addDependency(attachment);

        // Create routes from the transit subnets to the firewall endpoints
        vpc.selectSubnets({ subnetGroupName: 'transit' }).subnets.forEach(
            ({ availabilityZone, routeTable }, i) =>
                new cdk.aws_ec2.CfnRoute(this, `TransitToFirewall_${i + 1}`, {
                    destinationCidrBlock: '0.0.0.0/0',
                    routeTableId: routeTable.routeTableId,
                    vpcEndpointId: firewallEndpointIds[availabilityZone] ?? Object.values(firewallEndpointIds)[0],
                }),
        );

        // Create routes from the firewall endpoint subnets to the NAT gateways
        vpc.selectSubnets({ subnetGroupName: 'firewall' }).subnets.forEach(
            ({ routeTable, subnetId }, i) =>
                new cdk.aws_ec2.CfnRoute(this, `FirewallToGateway_${i + 1}`, {
                    destinationCidrBlock: '0.0.0.0/0',
                    natGatewayId: (natGateways.find((g) => g.subnetId === subnetId) ?? natGateways[0]).attrNatGatewayId,
                    routeTableId: routeTable.routeTableId,
                }),
        );

        // Create routes from the NAT gateway subnets to the internet gateway
        vpc.selectSubnets({ subnetGroupName: 'nat' }).subnets.forEach(
            ({ routeTable }, i) =>
                new cdk.aws_ec2.CfnRoute(this, `GatewayToInternet_${i + 1}`, {
                    destinationCidrBlock: '0.0.0.0/0',
                    gatewayId: internetGateway.attrInternetGatewayId,
                    routeTableId: routeTable.routeTableId,
                }),
        );

        // Inbound traffic routing

        // Collect the CIDRs that we allowed outbound traffic for
        const cidrs = Object.values(props.cidrFqdns).flatMap(({ cidrs }) => cidrs);

        // Create routes from the NAT gateway subnets to the firewall endpoints
        vpc.selectSubnets({ subnetGroupName: 'nat' }).subnets.forEach(({ availabilityZone, routeTable }, i) =>
            cidrs.forEach(
                (destinationCidrBlock) =>
                    new cdk.aws_ec2.CfnRoute(this, `GatewayToFirewall_${i + 1}`, {
                        destinationCidrBlock,
                        routeTableId: routeTable.routeTableId,
                        vpcEndpointId: firewallEndpointIds[availabilityZone] ?? Object.values(firewallEndpointIds)[0],
                    }),
            ),
        );

        // Create routes from the firewall endpoint subnets to the transit gateway - depend on the attachment
        vpc.selectSubnets({ subnetGroupName: 'firewall' }).subnets.forEach(({ routeTable }, i) =>
            cidrs.forEach((destinationCidrBlock) =>
                new cdk.aws_ec2.CfnRoute(this, `FirewallToTransit_${i + 1}`, {
                    destinationCidrBlock,
                    routeTableId: routeTable.routeTableId,
                    transitGatewayId: this._transitGateway.attrId,
                }).node.addDependency(attachment),
            ),
        );
    }

    /**
     * Given availability zones, maps out the matching endpoint id for each.
     * Each AZ MUST contain a firewall endpoint, otherwise behaviour is undefined.
     */
    private retrieveFirewallEndpointIds(firewallEndpointIds: string[], availabilityZones: string[]) {
        // Construct a map to hold the endpoint id for each AZ
        const endpointMap: { [az: string]: string } = {};
        // Join together each endpoint id from the list token into a single comma separated string
        const joinedEndpointIds = cdk.Fn.join(',', firewallEndpointIds);
        for (const az of availabilityZones) {
            // Split the joined string based on the AZ and colon, then grab the second element which contains the endpoint id, and the remainder of the string
            // 'ap-southeast-2a:vpce-123456789012,ap-southeast-2b:vpce-123456789012' => ['', 'vpce-123456789012,ap-southeast-2b:vpce-123456789012']
            const remainder = cdk.Fn.split(`${az}:`, joinedEndpointIds, 2)[1];
            // Split the remainder string on the comma and take the first element, giving us the endpoint id
            // 'vpce-123456789012,ap-southeast-2b:vpce-123456789012' => ['vpce-123456789012', 'ap-southeast-2b:vpce-123456789012']
            const endpointId = cdk.Fn.split(',', remainder, 2)[0];
            // Store the endpoint id in the AZ map
            endpointMap[az] = endpointId;
        }
        return endpointMap;
    }

    public get transitGateway() {
        return this._transitGateway;
    }
}

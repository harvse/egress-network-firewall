import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

interface WorkloadStackProps extends cdk.StackProps {
    /**
     * The CIDR block to use for the VPC.
     */
    readonly cidrBlock: string;

    /**
     * The transit gateway to attach the VPC to.
     */
    readonly transitGateway: cdk.aws_ec2.CfnTransitGateway;
}

export class WorkloadStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: WorkloadStackProps) {
        super(scope, id, props);

        // Create a VPC without any gateways to avoid CDK default routing, and subnets for each purpose in each AZ
        const vpc = new cdk.aws_ec2.Vpc(this, 'Vpc', {
            createInternetGateway: false,
            ipAddresses: cdk.aws_ec2.IpAddresses.cidr(props.cidrBlock),
            natGateways: 0,
            subnetConfiguration: [
                { cidrMask: 28, name: 'instance', subnetType: cdk.aws_ec2.SubnetType.PRIVATE_ISOLATED },
                { name: 'transit', subnetType: cdk.aws_ec2.SubnetType.PRIVATE_ISOLATED },
            ],
        });

        // Attach the VPC to the transit gateway
        const attachment = new cdk.aws_ec2.CfnTransitGatewayAttachment(this, 'TransitGatewayAttachment', {
            subnetIds: vpc.selectSubnets({ subnetGroupName: 'transit' }).subnetIds,
            transitGatewayId: props.transitGateway.attrId,
            vpcId: vpc.vpcId,
        });

        // Setup routing from the instance subnets to the transit gateway - depend on the attachment
        vpc.selectSubnets({ subnetGroupName: 'instance' }).subnets.forEach(({ routeTable }, i) =>
            new cdk.aws_ec2.CfnRoute(this, `IsolatedToGateway_${i + 1}`, {
                routeTableId: routeTable.routeTableId,
                destinationCidrBlock: '0.0.0.0/0',
                transitGatewayId: attachment.transitGatewayId,
            }).node.addDependency(attachment),
        );

        // Create an instance with SSM permissions in an instance subnet
        new cdk.aws_ec2.Instance(this, 'Instance', {
            instanceType: cdk.aws_ec2.InstanceType.of(cdk.aws_ec2.InstanceClass.T3, cdk.aws_ec2.InstanceSize.MICRO),
            machineImage: cdk.aws_ec2.MachineImage.latestAmazonLinux2023(),
            ssmSessionPermissions: true,
            vpc,
            vpcSubnets: { subnetGroupName: 'instance' },
        });
    }
}

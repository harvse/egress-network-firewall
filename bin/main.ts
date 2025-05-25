#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import 'source-map-support/register';
import { NetworkStack } from '../stacks/network-stack';
import { WorkloadStack } from '../stacks/workload-stack';

const app = new cdk.App({});

const env = {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
};

const workloadCidr = '10.1.0.0/16';

const networkStack = new NetworkStack(app, 'NetworkStack', {
    cidrFqdns: {
        workload: {
            cidrs: [workloadCidr],
            fqdns: [
                'google.com',
                'ssm.ap-southeast-2.amazonaws.com',
                'ec2messages.ap-southeast-2.amazonaws.com',
                'ssmmessages.ap-southeast-2.amazonaws.com',
            ],
        },
    },
    env,
});

new WorkloadStack(app, 'WorkloadStack', {
    cidrBlock: workloadCidr,
    env,
    transitGateway: networkStack.transitGateway,
});

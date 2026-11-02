# ALB Troubleshooter

A read-only Python/boto3 command-line tool for investigating traffic problems from an Application Load Balancer through its EC2 targets.

## Current checks

- Load balancer state, DNS name, VPC, subnets, and listener forwarding actions
- Target group membership and target health, including AWS health reason codes
- EC2 instance state and system/instance status checks
- ALB and target security group IDs, target ingress from the ALB security group, ALB egress to target ports, and listener ingress sources
- ALB node private addresses and subnet network ACL rules
- NACL first-match evaluation for ALB-to-target traffic and the ephemeral-port return path
- Route table associations and routes for ALB and target subnets
- Most-specific matching routes for ALB-to-target and return traffic
- Internet gateway route and VPC attachment checks for internet-facing ALBs

The command only makes AWS read requests. It does not change AWS resources.

## Requirements

- Python 3.10 or newer
- AWS credentials configured through the AWS CLI, an AWS profile, environment credentials, or another boto3-supported method
- IAM permission to call the read operations listed below

## Install

From this directory, run:

```powershell
python -m pip install -e .
```

## Run

```powershell
alb-troubleshooter --load-balancer sample-web-alb --region us-west-2
```

You can provide either a load balancer name or its ARN. Credentials and region are passed to boto3; this tool does not collect or store credentials.

## Example output

See [sample output](examples/sample-output.txt). It uses fictional AWS identifiers and private addresses, not output from a real account.

## IAM read permissions

The calling identity needs these actions for the checks currently implemented:

- `elasticloadbalancing:DescribeLoadBalancers`
- `elasticloadbalancing:DescribeListeners`
- `elasticloadbalancing:DescribeTargetHealth`
- `ec2:DescribeInstanceStatus`
- `ec2:DescribeInstances`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkInterfaces`
- `ec2:DescribeNetworkAcls`
- `ec2:DescribeRouteTables`
- `ec2:DescribeInternetGateways`

Scope permissions to the relevant region and resources where AWS supports resource-level authorization. Some EC2 describe actions require `Resource: "*"`.

## Diagnostic limits

- Security group evaluation currently recognizes direct security group references and IPv4 CIDR egress. Prefix-list egress and CIDR-based target ingress are reported as unchecked.
- NACL path evaluation covers IPv4 TCP target traffic and the 1024–65535 return-port range. It reports configured rules; it cannot prove that packets are flowing.
- Route reporting shows configured routes and the most-specific CIDR route candidates. Prefix-list route contents and every intermediate network device or external network path are not validated.
- Optional SSM application-service checks and HTTP/HTTPS probes are not implemented yet.

## Later enhancements

- DNS resolution and TLS certificate inspection
- CloudWatch logs and metrics
- Optional SSM service checks and ALB HTTP/HTTPS probes
- Broader security group support for prefix lists and CIDR-based target ingress

The tool is under active development; check output and diagnostic limits when using it to troubleshoot production incidents.

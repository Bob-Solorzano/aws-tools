# ALB Troubleshooter

A read-only command-line tool for diagnosing traffic problems across an AWS VPC,
from an Application Load Balancer through EC2 instances to an application.

## Planned checks

- ALB state, listeners, and forwarding rules
- Target group membership and target health
- EC2 state and AWS status checks
- Optional read-only application service check through SSM
- Security groups, network ACLs, route tables, and relevant gateways
- Optional HTTP/HTTPS request through the ALB

## Later enhancements

- DNS resolution
- TLS certificate inspection
- CloudWatch logs and metrics

## Status

Planning and initial setup. Checks are not implemented yet.
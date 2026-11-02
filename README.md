# AWS Tools

A collection of independent Python command-line tools for troubleshooting AWS services. The tools use boto3 and are designed to keep each service tool independently installable.

## Tools

- [ALB Troubleshooter](tools/alb-troubleshooter/README.md) — read-only checks for an Application Load Balancer to EC2 traffic path.
- [Sanitized example output](tools/alb-troubleshooter/examples/sample-output.txt) — sample report with fictional AWS identifiers and private addresses.

## Project status

The ALB Troubleshooter is in active development. It currently reports load balancer listeners and target health, EC2 status checks, relevant security group rules, network ACL rules and path evaluation, route tables, and gateway routes.

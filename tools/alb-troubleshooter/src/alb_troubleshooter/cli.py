import argparse
import sys
import ipaddress

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def parse_args():
    parser = argparse.ArgumentParser(
        description="Read-only diagnostics for an AWS ALB traffic path."
    )
    parser.add_argument(
        "--load-balancer",
        required=True,
        help="Load balancer name or ARN",
    )
    parser.add_argument(
        "--region",
        required=True,
        help="AWS region, for example us-west-2",
    )
    return parser.parse_args()

def permission_allows_tcp_port(permission, port):
    protocol = permission.get("IpProtocol")

    if protocol == "-1":
        return True

    if protocol not in ("tcp", "6"):
        return False

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    return (
        from_port is not None
        and to_port is not None
        and from_port <= port <= to_port
    )

def egress_permission_allows_target(
    permission, port, target_security_group_ids, target_private_ip
):
    if not permission_allows_tcp_port(permission, port):
        return False

    destination_group_ids = {
        pair.get("GroupId")
        for pair in permission.get("UserIdGroupPairs", [])
    }
    if destination_group_ids & target_security_group_ids:
        return True

    if not target_private_ip:
        return False

    target_ip = ipaddress.ip_address(target_private_ip)
    return any(
        target_ip in ipaddress.ip_network(rule["CidrIp"])
        for rule in permission.get("IpRanges", [])
    )

def format_nacl_rule(rule):
    protocol = {
        "-1": "ALL",
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
    }.get(str(rule["Protocol"]), str(rule["Protocol"]))

    if "PortRange" in rule:
        start = rule["PortRange"]["From"]
        end = rule["PortRange"]["To"]
        ports = str(start) if start == end else f"{start}-{end}"
    elif "IcmpTypeCode" in rule:
        icmp = rule["IcmpTypeCode"]
        ports = f"type {icmp['Type']} code {icmp['Code']}"
    else:
        ports = "all ports"

    cidr = rule.get("CidrBlock") or rule.get("Ipv6CidrBlock") or "no CIDR"

    return (
        f"{rule['RuleNumber']} {rule['RuleAction'].upper()} "
        f"{protocol} {ports} {cidr}"
    )

def first_matching_nacl_rule(nacl, egress, peer_ip, protocol, port):
    peer_address = ipaddress.ip_address(peer_ip)

    for rule in sorted(nacl["Entries"], key=lambda item: item["RuleNumber"]):
        if rule["Egress"] != egress:
            continue

        rule_protocol = str(rule["Protocol"])
        if rule_protocol not in ("-1", str(protocol)):
            continue

        cidr = rule.get("CidrBlock") or rule.get("Ipv6CidrBlock")
        if not cidr:
            continue

        network = ipaddress.ip_network(cidr, strict=False)
        if network.version != peer_address.version:
            continue
        if peer_address not in network:
            continue

        if rule_protocol != "-1":
            port_range = rule.get("PortRange")
            if not port_range:
                continue
            if not port_range["From"] <= port <= port_range["To"]:
                continue

        return rule

    return None


def evaluate_nacl_port_range(nacl, egress, peer_ip, protocol, start, end):
    boundaries = {start, end + 1}
    peer_address = ipaddress.ip_address(peer_ip)

    for rule in nacl["Entries"]:
        if rule["Egress"] != egress:
            continue

        rule_protocol = str(rule["Protocol"])
        if rule_protocol not in ("-1", str(protocol)) or rule_protocol == "-1":
            continue

        cidr = rule.get("CidrBlock") or rule.get("Ipv6CidrBlock")
        if not cidr:
            continue

        network = ipaddress.ip_network(cidr, strict=False)
        if network.version != peer_address.version or peer_address not in network:
            continue

        port_range = rule.get("PortRange")
        if not port_range:
            continue

        rule_start = max(start, port_range["From"])
        rule_end = min(end, port_range["To"])
        if rule_start <= rule_end:
            boundaries.add(rule_start)
            boundaries.add(rule_end + 1)

    used_rule_numbers = set()

    for port in sorted(boundaries)[:-1]:
        rule = first_matching_nacl_rule(
            nacl, egress, peer_ip, protocol, port
        )
        if rule is None or rule["RuleAction"] != "allow":
            return False, port, rule

        used_rule_numbers.add(rule["RuleNumber"])

    return True, sorted(used_rule_numbers), None

def permission_sources(permission):
    sources = []

    sources.extend(
        f"IPv4 {item['CidrIp']}"
        for item in permission.get("IpRanges", [])
    )
    sources.extend(
        f"IPv6 {item['CidrIpv6']}"
        for item in permission.get("Ipv6Ranges", [])
    )
    sources.extend(
        f"security group {item.get('GroupId', 'unknown')}"
        for item in permission.get("UserIdGroupPairs", [])
    )
    sources.extend(
        f"prefix list {item.get('PrefixListId', 'unknown')}"
        for item in permission.get("PrefixListIds", [])
    )

    return sources or ["source not returned"]

def main():
    args = parse_args()
    elbv2 = boto3.client("elbv2", region_name=args.region)

    lookup = (
        {"LoadBalancerArns": [args.load_balancer]}
        if args.load_balancer.startswith("arn:")
        else {"Names": [args.load_balancer]}
    )

    try:
        response = elbv2.describe_load_balancers(**lookup)
        load_balancer = response["LoadBalancers"][0]
        alb_subnet_ids = {
            zone["SubnetId"]
            for zone in load_balancer["AvailabilityZones"]
        }
        listeners = elbv2.describe_listeners(
            LoadBalancerArn=load_balancer["LoadBalancerArn"]
        )["Listeners"]
    except (BotoCoreError, ClientError, IndexError, KeyError) as error:
        print(f"Could not inspect the load balancer: {error}", file=sys.stderr)
        return 1

    state = load_balancer["State"]
    print(f"Load balancer: {load_balancer['LoadBalancerName']}")
    print(f"ARN:           {load_balancer['LoadBalancerArn']}")
    print(f"Type:          {load_balancer['Type']}")
    print(f"State:         {state['Code']}")
    print(f"DNS name:      {load_balancer['DNSName']}")
    print(f"VPC:           {load_balancer['VpcId']}")
    print(f"Subnets:       {', '.join(load_balancer['AvailabilityZones'][i]['SubnetId'] for i in range(len(load_balancer['AvailabilityZones'])))}")

    target_group_arns = set()

    print("\nListeners:")
    for listener in listeners:
        print(f"  {listener['Protocol']} :{listener['Port']}")

        listener_target_group_arns = set()

        for action in listener["DefaultActions"]:
            if action["Type"] != "forward":
                continue

            target_group_arn = action.get("TargetGroupArn")
            if target_group_arn:
                listener_target_group_arns.add(target_group_arn)

            forward_config = action.get("ForwardConfig", {})
            for target_group in forward_config.get("TargetGroups", []):
                listener_target_group_arns.add(
                    target_group["TargetGroupArn"]
                )

        for arn in sorted(listener_target_group_arns):
            target_group_arns.add(arn)
            print(f"    forwards to: {arn}")

    instance_ids = set()
    target_ports_by_instance = {}

    print("\nTarget health:")
    if not target_group_arns:
        print("  No forwarded target groups found.")
    else:
        for target_group_arn in sorted(target_group_arns):
            response = elbv2.describe_target_health(
                TargetGroupArn=target_group_arn
            )
            descriptions = response["TargetHealthDescriptions"]

            print(f"  Target group: {target_group_arn}")
            if not descriptions:
                print("    No registered targets.")
                continue

            for target in descriptions:
                target_id = target["Target"]["Id"]
                if target_id.startswith("i-"):
                    instance_ids.add(target_id)
                target_port = target["Target"].get("Port", "default")
                if target_id.startswith("i-"):
                    target_ports_by_instance.setdefault(target_id, set()).add(
                        target_port
                    )
                health = target["TargetHealth"]
                detail = health.get("Reason") or health.get("Description") or ""

                print(
                    f"    {target_id}:{target_port} "
                    f"{health['State']}"
                    f"{f' — {detail}' if detail else ''}"
                )

    print("\nEC2 instance status:")
    if not instance_ids:
        print("  No EC2 instance targets found.")
    else:
        ec2 = boto3.client("ec2", region_name=args.region)
        response = ec2.describe_instance_status(
            InstanceIds=sorted(instance_ids),
            IncludeAllInstances=True,
        )

        statuses = {
            item["InstanceId"]: item
            for item in response["InstanceStatuses"]
        }

        for instance_id in sorted(instance_ids):
            item = statuses.get(instance_id)
            if item is None:
                print(f"  {instance_id}: no EC2 status record returned")
                continue

            state = item["InstanceState"]["Name"]
            system_status = item["SystemStatus"]["Status"]
            instance_status = item["InstanceStatus"]["Status"]

            print(f"  {instance_id}: {state}")
            print(f"    System check:   {system_status}")
            print(f"    Instance check: {instance_status}")

    print("\nSecurity groups:")

    alb_security_group_ids = set(load_balancer.get("SecurityGroups", []))
    print("  Load balancer:")
    for group_id in sorted(alb_security_group_ids):
        print(f"    {group_id}")

    instance_security_group_ids = {}
    instance_private_ips = {}
    instance_subnet_ids = {}
    if instance_ids:
        response = ec2.describe_instances(
            InstanceIds=sorted(instance_ids)
        )

        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                group_ids = {
                    group["GroupId"]
                    for group in instance.get("SecurityGroups", [])
                }
                instance_security_group_ids[instance["InstanceId"]] = group_ids
                instance_private_ips[instance["InstanceId"]] = instance.get(
                    "PrivateIpAddress"
                )
                instance_subnet_ids[instance["InstanceId"]] = instance.get(
                    "SubnetId"
                )

        print("  EC2 targets:")
        for instance_id in sorted(instance_ids):
            group_ids = sorted(
                instance_security_group_ids.get(instance_id, set())
            )
            print(f"    {instance_id}: {', '.join(group_ids) or 'none'}")

    all_security_group_ids = set(alb_security_group_ids)
    for group_ids in instance_security_group_ids.values():
        all_security_group_ids.update(group_ids)

    response = ec2.describe_security_groups(
        GroupIds=sorted(all_security_group_ids)
    )
    security_groups_by_id = {
        group["GroupId"]: group
        for group in response["SecurityGroups"]
    }

    print("\nTarget ingress from ALB security group:")
    for instance_id in sorted(target_ports_by_instance):
        target_group_ids = instance_security_group_ids.get(instance_id, set())

        for port in sorted(target_ports_by_instance[instance_id]):
            matching_group_ids = []

            for group_id in target_group_ids:
                group = security_groups_by_id.get(group_id, {})
                for permission in group.get("IpPermissions", []):
                    if not permission_allows_tcp_port(permission, port):
                        continue

                    source_group_ids = {
                        pair.get("GroupId")
                        for pair in permission.get("UserIdGroupPairs", [])
                    }
                    if source_group_ids & alb_security_group_ids:
                        matching_group_ids.append(group_id)

            if matching_group_ids:
                groups = ", ".join(sorted(set(matching_group_ids)))
                print(
                    f"  {instance_id}:{port} TCP: "
                    f"ALB SG reference allowed by {groups}"
                )
            else:
                print(
                    f"  {instance_id}:{port} TCP: "
                    "no direct ALB SG reference found "
                    "(CIDR rules not checked)"
                )

    print("\nALB security group egress to targets:")
    for instance_id in sorted(target_ports_by_instance):
        target_group_ids = instance_security_group_ids.get(instance_id, set())
        target_private_ip = instance_private_ips.get(instance_id)

        for port in sorted(target_ports_by_instance[instance_id]):
            matching_alb_group_ids = []

            for group_id in alb_security_group_ids:
                group = security_groups_by_id.get(group_id, {})
                if any(
                    egress_permission_allows_target(
                        permission,
                        port,
                        target_group_ids,
                        target_private_ip,
                    )
                    for permission in group.get("IpPermissionsEgress", [])
                ):
                    matching_alb_group_ids.append(group_id)

            if matching_alb_group_ids:
                groups = ", ".join(sorted(matching_alb_group_ids))
                print(
                    f"  {instance_id}:{port} TCP: "
                    f"allowed by {groups}"
                )
            else:
                print(
                    f"  {instance_id}:{port} TCP: "
                    "no matching SG or IPv4 CIDR egress rule found "
                    "(prefix-list rules not checked)"
                )

    print("\nALB listener ingress:")
    for listener in listeners:
        protocol = listener["Protocol"]
        port = listener["Port"]
        matching_rules = set()

        for group_id in alb_security_group_ids:
            group = security_groups_by_id.get(group_id, {})

            for permission in group.get("IpPermissions", []):
                if permission_allows_tcp_port(permission, port):
                    for source in permission_sources(permission):
                        matching_rules.add((group_id, source))

        print(f"  {protocol} :{port}")
        if matching_rules:
            for group_id, source in sorted(matching_rules):
                print(f"    {group_id} allows from {source}")
        else:
            print("    No matching TCP ingress rule found.")
            
    subnet_context = {
        subnet_id: ["ALB subnet"]
        for subnet_id in alb_subnet_ids
    }

    for instance_id, subnet_id in instance_subnet_ids.items():
        if subnet_id:
            subnet_context.setdefault(subnet_id, []).append(
                f"EC2 target {instance_id}"
            )

    alb_id = load_balancer["LoadBalancerArn"].split("/")[-1]
    alb_description = (
        f"ELB app/{load_balancer['LoadBalancerName']}/{alb_id}"
    )

    eni_response = ec2.describe_network_interfaces(
        Filters=[
            {
                "Name": "description",
                "Values": [alb_description],
            }
        ]
    )

    alb_private_ips_by_subnet = {}
    for interface in eni_response["NetworkInterfaces"]:
        private_ips = {
            address["PrivateIpAddress"]
            for address in interface.get("PrivateIpAddresses", [])
        }
        if private_ips:
            alb_private_ips_by_subnet.setdefault(
                interface["SubnetId"], set()
            ).update(private_ips)

    print("\nALB node addresses:")
    if alb_private_ips_by_subnet:
        for subnet_id in sorted(alb_private_ips_by_subnet):
            addresses = ", ".join(
                sorted(alb_private_ips_by_subnet[subnet_id])
            )
            print(f"  {subnet_id}: {addresses}")
    else:
        print("  No ALB network interfaces found.")

    nacl_response = ec2.describe_network_acls(
        Filters=[
            {
                "Name": "association.subnet-id",
                "Values": sorted(subnet_context),
            }
        ]
    )

    nacl_by_subnet = {}
    for nacl in nacl_response["NetworkAcls"]:
        for association in nacl["Associations"]:
            subnet_id = association.get("SubnetId")
            if subnet_id in subnet_context:
                nacl_by_subnet[subnet_id] = nacl

    print("\nNetwork ACLs:")
    for subnet_id in sorted(subnet_context):
        roles = ", ".join(sorted(set(subnet_context[subnet_id])))
        nacl = nacl_by_subnet.get(subnet_id)

        print(f"  Subnet {subnet_id} ({roles})")
        if nacl is None:
            print("    No associated network ACL returned.")
            continue

        print(f"    NACL: {nacl['NetworkAclId']}")

        for is_egress, label in ((False, "Ingress"), (True, "Egress")):
            rules = sorted(
                (
                    rule
                    for rule in nacl["Entries"]
                    if rule["Egress"] == is_egress
                ),
                key=lambda rule: rule["RuleNumber"],
            )

            print(f"    {label}:")
            for rule in rules:
                print(f"      {format_nacl_rule(rule)}")

    print("\nNACL traffic path:")
    ephemeral_start = 1024
    ephemeral_end = 65535

    for instance_id in sorted(target_ports_by_instance):
        target_ip = instance_private_ips.get(instance_id)
        target_subnet_id = instance_subnet_ids.get(instance_id)
        target_nacl = nacl_by_subnet.get(target_subnet_id)

        if not target_ip or not target_nacl:
            print(f"  {instance_id}: missing target IP or subnet NACL.")
            continue

        for port in sorted(target_ports_by_instance[instance_id]):
            if not isinstance(port, int):
                print(f"  {instance_id}: unsupported target port {port}.")
                continue

            for alb_subnet_id, alb_ips in sorted(
                alb_private_ips_by_subnet.items()
            ):
                alb_nacl = nacl_by_subnet.get(alb_subnet_id)
                if not alb_nacl:
                    continue

                for alb_ip in sorted(alb_ips):
                    print(
                        f"  ALB {alb_ip} -> "
                        f"{instance_id} ({target_ip}):{port}"
                    )

                    checks = [
                        (
                            "ALB subnet egress to target",
                            alb_nacl,
                            True,
                            target_ip,
                            port,
                            port,
                        ),
                        (
                            "Target subnet ingress from ALB",
                            target_nacl,
                            False,
                            alb_ip,
                            port,
                            port,
                        ),
                        (
                            "Target subnet egress return ephemeral",
                            target_nacl,
                            True,
                            alb_ip,
                            ephemeral_start,
                            ephemeral_end,
                        ),
                        (
                            "ALB subnet ingress return ephemeral",
                            alb_nacl,
                            False,
                            target_ip,
                            ephemeral_start,
                            ephemeral_end,
                        ),
                    ]

                    for label, nacl, egress, peer_ip, start, end in checks:
                        allowed, detail, blocking_rule = (
                            evaluate_nacl_port_range(
                                nacl, egress, peer_ip, 6, start, end
                            )
                        )

                        if allowed:
                            rule_numbers = ", ".join(
                                str(number) for number in detail
                            )
                            print(
                                f"    {label}: ALLOW "
                                f"(rule {rule_numbers})"
                            )
                        elif blocking_rule is None:
                            print(
                                f"    {label}: implicit DENY at port {detail}"
                            )
                        else:
                            print(
                                f"    {label}: "
                                f"{blocking_rule['RuleAction'].upper()} "
                                f"rule {blocking_rule['RuleNumber']} "
                                f"at port {detail}"
                            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
---
title: "VNX-TF-002 – Terraform AWS Security Group with Unrestricted Ingress (0.0.0.0/0)"
description: "Detect AWS security group ingress in Terraform that admits any address (0.0.0.0/0 or ::/0) through inline ingress blocks (block or attribute form), aws_security_group_rule, aws_vpc_security_group_ingress_rule or the terraform-aws-modules security-group module, except a listener on exactly port 80 or 443."
---

## Overview

This rule flags Terraform `.tf` files where `cidr_blocks` or `ipv6_cidr_blocks` contains `"0.0.0.0/0"` or `"::/0"` (on one line or in a list spread over several) inside an `ingress` block of `aws_security_group` or an `aws_security_group_rule` with `type = "ingress"`, and where `cidr_ipv4`/`cidr_ipv6` is `0.0.0.0/0`/`::/0` in an `aws_vpc_security_group_ingress_rule`. Egress, routes and network ACLs are not reported, nor are restricted or variable CIDRs, and ingress limited to exactly port 80 or exactly port 443 is treated as a public web listener that is open by design.

The rule reads the enclosing block of each CIDR attribute rather than searching nearby lines for the word `ingress`, so an `egress` block next to an `ingress` block is not reported. AWS security groups act as virtual firewalls for EC2 instances, RDS databases, Lambda functions, EKS clusters, and other resources. An overly permissive ingress rule on any of these resources eliminates one of the most important layers of defense against unauthorized access.

This rule corresponds to [CWE-1220: Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html).

**Severity:** High | **CWE:** [CWE-1220 – Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html)

## Why This Matters

Security groups are the primary network-level access control in AWS. When a security group allows traffic from `0.0.0.0/0`, the protected resource is reachable from anywhere on the internet. This dramatically expands the attack surface: automated scanners probe every public IP address for open ports, and any vulnerability in the exposed service — an unpatched CVE, a weak password, or a misconfigured endpoint — can be exploited by attackers worldwide.

The practical consequences depend on what service is exposed. An SSH port (22) open to `0.0.0.0/0` is continuously brute-forced within minutes of the resource becoming reachable. An RDS database port (3306, 5432) open to the internet allows direct authentication attacks against the database. An internal API endpoint that was only intended to receive traffic from other services within the VPC can be accessed directly, bypassing any application-level authentication layers that assumed internal network trust.

Even for services that are intended to be publicly accessible (web servers on port 443), best practice is to restrict as much as operationally possible and to use a load balancer or CDN as the public endpoint, keeping the underlying instances in private subnets.

## What Gets Flagged

```hcl
resource "aws_security_group" "bastion" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]       # FLAGGED: SSH open to the internet
  }
}

resource "aws_security_group_rule" "db_in" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]         # FLAGGED
}

resource "aws_vpc_security_group_ingress_rule" "all_v6" {
  cidr_ipv6   = "::/0"                # FLAGGED
  ip_protocol = "-1"
}
```

The `terraform-aws-modules/security-group` module is checked too: `ingress_cidr_blocks = ["0.0.0.0/0"]` with `ingress_rules = ["ssh-tcp"]`, and `cidr_blocks = "0.0.0.0/0"` in an `ingress_with_cidr_blocks` object on a port other than 80 or 443.

Not flagged: `egress` blocks, `aws_route` destinations, `cidr_blocks = ["10.0.0.0/8"]`, or an ALB ingress with `from_port = 443` and `to_port = 443`.

## Remediation

1. **Restrict ingress CIDR blocks to only the IP ranges that legitimately need access.** For internal services, use the VPC CIDR. For services accessed by specific offices or partners, use their IP ranges. For public-facing services, use an ALB or NLB in front:

```hcl
# SAFE: restrict SSH to a specific bastion or corporate IP range
resource "aws_security_group" "bastion" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] # your corporate egress range
  }
}
```

2. **Use security group references instead of CIDR blocks for service-to-service communication.** Reference the source security group by ID rather than its IP range — this is more robust and requires no updates when IP addresses change:

```hcl
# SAFE: only allow traffic from the web tier security group
resource "aws_security_group_rule" "db_from_web" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.web.id
  security_group_id        = aws_security_group.database.id
}
```

3. **Place services that do not need to be internet-facing in private subnets** and ensure their security groups only accept traffic from within the VPC or from a load balancer.

## References

- [CWE-1220: Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html)
- [AWS Security Groups – Inbound and outbound rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- [CIS AWS Foundations Benchmark – VPC and security group controls](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [Terraform aws_security_group documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group)

---
title: "VNX-TF-003 – Terraform AWS RDS Instance Publicly Accessible"
description: "Detect AWS RDS database instances configured with publicly_accessible = true in Terraform, which exposes the database endpoint directly to the internet."
---

## Overview

This rule flags Terraform `.tf` files where an `aws_db_instance`, `aws_rds_cluster`, or `aws_db_cluster` resource has `publicly_accessible = true`. When this setting is enabled, AWS assigns a publicly routable DNS endpoint to the database instance, making it reachable from any IP address on the internet (subject to security group rules).

Database instances contain an application's most sensitive data: user records, transaction history, session information, and application state. Direct internet exposure of a database endpoint dramatically increases the risk of unauthorized access through credential brute-forcing, exploitation of database engine vulnerabilities, and attacks against the authentication protocol itself.

This rule corresponds to [CWE-1220: Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html).

**Severity:** High | **CWE:** [CWE-1220 – Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html)

## Why This Matters

Database services are among the highest-value targets in any infrastructure. A successful unauthorized connection to a production database typically results in complete data exfiltration, as the attacker gains access to the entire dataset through standard query interfaces without needing any application-level exploits.

Internet-exposed RDS endpoints face continuous automated attacks. Within hours of a new database instance becoming publicly accessible, automated scanners will identify the open port, enumerate the database version, and attempt authentication with common credential sets. MySQL, PostgreSQL, and MSSQL all have well-documented default accounts and authentication bypass vulnerabilities that are continuously probed by attackers.

Even when strong passwords are used, a publicly accessible database endpoint provides no defence in depth. If a zero-day vulnerability is discovered in the database engine, all publicly accessible instances become immediately exploitable. Keeping the database in a private subnet means an attacker must first compromise a system inside the VPC before they can even reach the database, providing time to detect and respond.

## What Gets Flagged

The rule matches `.tf` files where `publicly_accessible = true` appears within the context of an RDS resource block.

```hcl
# FLAGGED: RDS instance accessible from the internet
resource "aws_db_instance" "app_db" {
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  publicly_accessible  = true
  username             = "dbadmin"
  password             = var.db_password
}

# FLAGGED: Aurora cluster with public endpoint
resource "aws_rds_cluster" "aurora" {
  cluster_identifier   = "aurora-cluster"
  publicly_accessible  = true
}
```

## Remediation

1. **Set `publicly_accessible = false` and place the instance in private subnets.** This is the baseline secure configuration for any database that should only be accessed by application servers within the same VPC:

```hcl
# SAFE: RDS in private subnets, not publicly accessible
resource "aws_db_instance" "app_db" {
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name

  vpc_security_group_ids = [aws_security_group.database.id]
}

resource "aws_db_subnet_group" "private" {
  subnet_ids = var.private_subnet_ids
}
```

2. **Use a bastion host or AWS Systems Manager Session Manager for administrative access.** If developers need direct database access for debugging, route the connection through a bastion in a private subnet or use AWS SSM port forwarding rather than making the database publicly accessible:

```bash
# SAFE: SSM port forwarding for local access — no public endpoint needed
aws ssm start-session \
  --target i-0123456789abcdef0 \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters "host=mydb.cluster.us-east-1.rds.amazonaws.com,portNumber=5432,localPortNumber=5432"
```

3. **Use IAM authentication for RDS** to avoid long-lived passwords entirely, requiring short-lived tokens generated from IAM credentials.

## References

- [CWE-1220: Insufficient Granularity of Access Control](https://cwe.mitre.org/data/definitions/1220.html)
- [AWS RDS – Controlling access with security groups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html)
- [AWS RDS – Hiding a DB instance in a VPC](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html)
- [CIS AWS Foundations Benchmark – RDS controls](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [Terraform aws_db_instance documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance)

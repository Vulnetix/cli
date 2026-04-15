---
title: "VNX-TF-007 – Terraform AWS EKS Cluster Public API Endpoint Enabled"
description: "Detect AWS EKS clusters in Terraform with the Kubernetes API server endpoint publicly accessible from the internet, increasing the attack surface for credential brute-force and CVE exploitation."
---

## Overview

This rule flags Terraform `.tf` files where an `aws_eks_cluster` resource either explicitly sets `endpoint_public_access = true` or omits the `endpoint_public_access` attribute in the `vpc_config` block (the default is public access enabled). The EKS API server endpoint is the control plane interface through which `kubectl` commands, CI/CD pipelines, and Kubernetes controllers communicate. When it is publicly accessible, any internet-connected host can attempt to authenticate against it.

A publicly accessible Kubernetes API server is a high-value target for several classes of attack: credential theft via brute-force or social engineering, exploitation of authentication vulnerabilities in the API server itself, and discovery of exposed control plane components via the unauthenticated `/version` and `/healthz` endpoints that leak cluster information.

This rule corresponds to [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html).

**Severity:** High | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

The Kubernetes API server is the most sensitive component of any Kubernetes cluster. Every administrative action — deploying workloads, reading secrets, modifying RBAC policies, accessing pod logs — flows through the API server. An attacker who can authenticate to the API server (or exploit an unauthenticated vulnerability in it) has complete control over all workloads running on the cluster.

EKS clusters running production workloads frequently have Kubernetes Secrets containing database credentials, API keys, TLS certificates, and cloud provider credentials. A compromised API server provides access to all of these. The attacker can also spawn privileged containers, mount host filesystems, access the EC2 instance metadata service from within pods, and ultimately achieve full control of the underlying EC2 worker nodes.

Public EKS endpoints face automated scanning that discovers new clusters within minutes. While AWS requires valid credentials to make most API calls, `kubectl` cluster CVEs (such as the path traversal vulnerability CVE-2018-1002105) have demonstrated that even partially unauthenticated access to a public API server can be leveraged to escalate privileges.

## What Gets Flagged

The rule matches `.tf` files where `endpoint_public_access = true` is set, or where an `aws_eks_cluster` resource does not include `endpoint_public_access = false` in its configuration.

```hcl
# FLAGGED: public API endpoint explicitly enabled
resource "aws_eks_cluster" "prod" {
  name     = "production"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids            = var.private_subnet_ids
    endpoint_public_access = true
  }
}

# FLAGGED: missing endpoint_public_access — defaults to true
resource "aws_eks_cluster" "prod" {
  name     = "production"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids = var.private_subnet_ids
    # endpoint_public_access not set — defaults to enabled
  }
}
```

## Remediation

1. **Set `endpoint_public_access = false` and `endpoint_private_access = true`.** Workers and management tooling should communicate with the API server via the private VPC endpoint:

```hcl
# SAFE: private-only EKS API endpoint
resource "aws_eks_cluster" "prod" {
  name     = "production"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}
```

2. **If public access is operationally necessary, restrict it to specific CIDR blocks** rather than allowing all internet traffic. Use `public_access_cidrs` to limit access to corporate VPN egress IPs or other known ranges:

```hcl
# ACCEPTABLE: public access restricted to specific IPs
vpc_config {
  endpoint_public_access  = true
  endpoint_private_access = true
  public_access_cidrs     = ["203.0.113.0/24"] # corporate VPN egress
}
```

3. **Use AWS VPN or Direct Connect for administrative access** to avoid requiring a public endpoint. CI/CD pipelines can reach the private endpoint by running within the VPC or through a VPN connection.

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [AWS EKS – Cluster endpoint access control](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html)
- [AWS EKS security best practices guide](https://aws.github.io/aws-eks-best-practices/security/docs/)
- [CIS AWS Foundations Benchmark – EKS controls](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [Terraform aws_eks_cluster documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster)

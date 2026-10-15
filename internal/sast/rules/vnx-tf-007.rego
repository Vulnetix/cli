package vulnetix.rules.vnx_tf_007

import rego.v1

metadata := {
	"id": "VNX-TF-007",
	"name": "Terraform AWS EKS cluster public API endpoint enabled",
	"description": "An EKS cluster's Kubernetes API server is reachable from the whole internet: endpoint_public_access = true in an aws_eks_cluster, or an aws_eks_cluster that does not set endpoint_public_access at all (the AWS default is a public endpoint), in either case without public_access_cidrs or with public_access_cidrs containing 0.0.0.0/0 (the default); or cluster_endpoint_public_access / endpoint_public_access = true in a terraform-aws-modules EKS module (a module whose source names eks) without a restricting *_public_access_cidrs list. Not reported: endpoint_public_access = false, a public endpoint restricted to specific CIDRs (or to a variable list), a value taken from a variable, an EKS module that leaves public access at its default (off), other resource types, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-007/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [200],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["eks", "kubernetes", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

_is_tf(path) if endswith(path, ".tofu")

# Index of the column-0 block header enclosing line i (the nearest one above).
_top(lines, i) := max(ks) if {
	ks := [k | some k in numbers.range(max([0, i - 400]), i); regex.match(`^[A-Za-z]`, lines[k])]
	count(ks) > 0
}

_top_end(lines, s) := min(array.concat([count(lines) - 1], [k |
	some k in numbers.range(s + 1, min([count(lines) - 1, s + 600]))
	startswith(lines[k], "}")
]))

_eks_module(lines, s) if {
	regex.match(`^module\s+"`, lines[s])
	some k in numbers.range(s + 1, _top_end(lines, s))
	regex.match(`^\s*source\s*=\s*"[^"]*eks`, lines[k])
}

# A public_access_cidrs list in the block that does not name 0.0.0.0/0, on
# its line or its continuation lines.
_restricted(lines, s, e, attr_re) if {
	some k in numbers.range(s + 1, e)
	regex.match(attr_re, lines[k])
	not _lists_any(lines, k, e)
}

_lists_any(lines, k, e) if contains(lines[k], "0.0.0.0/0")

_lists_any(lines, k, e) if {
	regex.match(`\[[^\]]*$`, lines[k])
	ends := [j | some j in numbers.range(k + 1, min([e, k + 12])); contains(lines[j], "]")]
	count(ends) > 0
	some j in numbers.range(k + 1, min(ends))
	contains(lines[j], "0.0.0.0/0")
}

_cluster_cidrs := `^\s*public_access_cidrs\s*=`

_module_cidrs := `^\s*(cluster_)?endpoint_public_access_cidrs\s*=`

_message := "EKS Kubernetes API endpoint is public to the internet; set endpoint_public_access = false (reach the API through a VPN, bastion or private link), or restrict public_access_cidrs to known address ranges"

# Explicit public endpoint on the cluster resource.
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	contains(content, "endpoint_public_access")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*endpoint_public_access\s*=\s*"?true`, line)
	s := _top(lines, i)
	regex.match(`^resource\s+"aws_eks_cluster"\s`, lines[s])
	not _restricted(lines, s, _top_end(lines, s), _cluster_cidrs)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Public endpoint left at the AWS default.
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	contains(content, "aws_eks_cluster")
	lines := split(content, "\n")
	some s, line in lines
	regex.match(`^resource\s+"aws_eks_cluster"\s+"[^"]+"\s*\{\s*$`, line)
	e := _top_end(lines, s)
	not _sets_public(lines, s, e)
	not _restricted(lines, s, e, _cluster_cidrs)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": s + 1,
		"snippet": line,
	}
}

_sets_public(lines, s, e) if {
	some k in numbers.range(s + 1, e)
	regex.match(`^\s*endpoint_public_access\s*=`, lines[k])
}

# terraform-aws-modules/eks with public access turned on.
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	contains(content, "endpoint_public_access")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*(cluster_)?endpoint_public_access\s*=\s*"?true`, line)
	s := _top(lines, i)
	_eks_module(lines, s)
	not _restricted(lines, s, _top_end(lines, s), _module_cidrs)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

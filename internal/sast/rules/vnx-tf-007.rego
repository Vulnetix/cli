package vulnetix.rules.vnx_tf_007

import rego.v1

metadata := {
	"id": "VNX-TF-007",
	"name": "Terraform AWS EKS cluster public API endpoint enabled",
	"description": "The EKS cluster Kubernetes API server endpoint is accessible from the internet (endpoint_public_access not explicitly disabled). A publicly reachable Kubernetes API increases the attack surface for credential brute-force and CVE exploitation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-007/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [200],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["eks", "kubernetes", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

# Explicit endpoint_public_access = true
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`endpoint_public_access\s*=\s*true`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "EKS cluster has endpoint_public_access = true; set endpoint_public_access = false and use a VPN or bastion host to access the Kubernetes API",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# aws_eks_cluster without endpoint_public_access = false
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`resource\s+"aws_eks_cluster"\s+"[^"]+"\s*\{`, line)
	window_end := min([count(lines) - 1, i + 40])
	window_lines := array.slice(lines, i, window_end + 1)
	window := concat("\n", window_lines)
	not contains(window, "endpoint_public_access")
	finding := {
		"rule_id": metadata.id,
		"message": "aws_eks_cluster resource missing endpoint_public_access = false in vpc_config; explicitly disable the public endpoint to reduce the attack surface",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_tf_002

import rego.v1

metadata := {
	"id": "VNX-TF-002",
	"name": "Terraform AWS security group with unrestricted ingress (0.0.0.0/0)",
	"description": "An AWS security group ingress rule allows traffic from any source (0.0.0.0/0 or ::/0). Overly permissive ingress rules expose services to the entire internet and increase the attack surface.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-002/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1220],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["security-group", "network", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"`, line)
	# Confirm it's inside an ingress block by checking nearby lines
	window_start := max([0, i - 10])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	contains(window, "ingress")
	finding := {
		"rule_id": metadata.id,
		"message": "Security group ingress rule allows traffic from 0.0.0.0/0; restrict the CIDR to only the IP ranges that legitimately need access to this service",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`ipv6_cidr_blocks\s*=\s*\[?\s*"::/0"`, line)
	window_start := max([0, i - 10])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	contains(window, "ingress")
	finding := {
		"rule_id": metadata.id,
		"message": "Security group ingress rule allows traffic from ::/0 (all IPv6); restrict the CIDR to only the IP ranges that legitimately need access to this service",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

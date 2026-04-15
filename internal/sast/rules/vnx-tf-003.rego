package vulnetix.rules.vnx_tf_003

import rego.v1

metadata := {
	"id": "VNX-TF-003",
	"name": "Terraform AWS RDS instance publicly accessible",
	"description": "An RDS database instance has publicly_accessible set to true, making it reachable from the internet. Database instances should only be accessible from within the VPC.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-003/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1220],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["rds", "database", "public-access", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`publicly_accessible\s*=\s*true`, line)
	window_start := max([0, i - 20])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	regex.match(`resource\s+"aws_(db_instance|rds_cluster|db_cluster)"`, window)
	finding := {
		"rule_id": metadata.id,
		"message": "RDS instance has publicly_accessible = true; set publicly_accessible = false and place the instance in a private subnet to prevent direct internet access",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

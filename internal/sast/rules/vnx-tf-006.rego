package vulnetix.rules.vnx_tf_006

import rego.v1

metadata := {
	"id": "VNX-TF-006",
	"name": "Terraform AWS EC2 instance metadata service v1 (IMDSv1) enabled",
	"description": "An EC2 instance allows the legacy IMDSv1 which does not require a PUT token. IMDSv1 is vulnerable to SSRF attacks — any application with the ability to make HTTP requests on the instance can request IAM credentials from the metadata endpoint.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-006/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1552.005"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["imds", "ssrf", "ec2", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

# Explicit http_tokens = "optional"
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`http_tokens\s*=\s*"optional"`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "EC2 instance metadata service IMDSv1 is enabled (http_tokens = \"optional\"); set http_tokens = \"required\" to enforce IMDSv2 and prevent SSRF-based credential theft",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# aws_instance without metadata_options block (defaults to IMDSv1)
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`resource\s+"aws_instance"\s+"[^"]+"\s*\{`, line)
	window_end := min([count(lines) - 1, i + 40])
	window_lines := array.slice(lines, i, window_end + 1)
	window := concat("\n", window_lines)
	not contains(window, "metadata_options")
	finding := {
		"rule_id": metadata.id,
		"message": "aws_instance resource missing metadata_options block; add metadata_options { http_tokens = \"required\" } to enforce IMDSv2 and prevent SSRF-based credential theft",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

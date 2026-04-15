package vulnetix.rules.vnx_tf_005

import rego.v1

metadata := {
	"id": "VNX-TF-005",
	"name": "Terraform AWS EBS volume unencrypted",
	"description": "An EBS volume or EBS-backed launch configuration does not have encryption enabled. Unencrypted EBS volumes expose data at rest to anyone who can access the underlying physical storage or a leaked snapshot.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-005/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [311],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["ebs", "encryption", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

# EBS volume with encrypted = false
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`encrypted\s*=\s*false`, line)
	window_start := max([0, i - 20])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	regex.match(`resource\s+"aws_(ebs_volume|ebs_snapshot|launch_configuration|launch_template)"`, window)
	finding := {
		"rule_id": metadata.id,
		"message": "EBS volume has encrypted = false; enable encryption (encrypted = true) and specify a KMS key via kms_key_id to protect data at rest",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# aws_ebs_volume block without any encrypted attribute
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	content := input.file_contents[path]
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`resource\s+"aws_ebs_volume"\s+"[^"]+"\s*\{`, line)
	# Find the end of this block
	window_end := min([count(lines) - 1, i + 30])
	window_lines := array.slice(lines, i, window_end + 1)
	window := concat("\n", window_lines)
	not contains(window, "encrypted")
	finding := {
		"rule_id": metadata.id,
		"message": "aws_ebs_volume resource missing encrypted attribute; add encrypted = true and specify a kms_key_id to protect data at rest",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

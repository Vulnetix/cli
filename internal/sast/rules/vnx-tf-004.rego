package vulnetix.rules.vnx_tf_004

import rego.v1

metadata := {
	"id": "VNX-TF-004",
	"name": "Terraform IAM policy with wildcard Action (*)",
	"description": "An IAM policy grants wildcard actions ('*') without a corresponding Deny statement. This violates the principle of least privilege and could allow an attacker who gains access to the role or user to perform any action on AWS resources.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-004/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [269],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1078"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["iam", "least-privilege", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\bAction\s*=\s*"?\*"?`, line)
	# Confirm context is an IAM policy resource (not a Deny effect)
	window_start := max([0, i - 20])
	window_end := min([count(lines) - 1, i + 10])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	regex.match(`aws_iam_(role_policy|policy|user_policy|group_policy)`, window)
	not regex.match(`Effect\s*=\s*"Deny"`, window)
	finding := {
		"rule_id": metadata.id,
		"message": "IAM policy grants wildcard Action = \"*\"; enumerate only the specific actions required and follow the principle of least privilege",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Also catch data.aws_iam_policy_document with actions = ["*"]
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`actions\s*=\s*\[\s*"\*"\s*\]`, line)
	window_start := max([0, i - 15])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	contains(window, "aws_iam_policy_document")
	not contains(window, "effect")
	finding := {
		"rule_id": metadata.id,
		"message": "IAM policy document statement uses actions = [\"*\"]; enumerate only the specific actions required and follow the principle of least privilege",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

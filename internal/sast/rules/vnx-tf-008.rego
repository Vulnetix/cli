package vulnetix.rules.vnx_tf_008

import rego.v1

metadata := {
	"id": "VNX-TF-008",
	"name": "Terraform AWS provider with hardcoded static credentials",
	"description": "The AWS Terraform provider block contains hardcoded access_key and/or secret_key values. Static credentials committed to source control can be extracted and used to gain unauthorised access to AWS resources.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-008/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["hardcoded-credentials", "secrets", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_tf(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(access_key|secret_key)\s*=\s*"[A-Za-z0-9+/]{16,}"`, line)
	# Ignore variable references and empty strings
	not regex.match(`\$\{|var\.|local\.`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded AWS credentials in provider block; use IAM instance roles, environment variables (AWS_ACCESS_KEY_ID), or a credentials file — never hardcode credentials in Terraform files",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_tf_008

import rego.v1

metadata := {
	"id": "VNX-TF-008",
	"name": "Terraform AWS provider with hardcoded static credentials",
	"description": "A literal AWS access key pair is written into Terraform: access_key, aws_access_key, aws_access_key_id or AWS_ACCESS_KEY_ID assigned a quoted AKIA/ASIA key id, or secret_key, aws_secret_key, aws_secret_access_key or AWS_SECRET_ACCESS_KEY assigned a quoted 40-character secret, in .tf, .tofu or .tfvars files (provider and s3 backend blocks, variable files, and function environment maps alike), and the value of an ECS-style { name = \"AWS_ACCESS_KEY_ID\" / \"AWS_SECRET_ACCESS_KEY\", value = \"...\" } environment entry whose value has the matching shape. Committed keys can be extracted from the repository and its history. Not reported: values from variables, data sources, interpolation or shared credential files, empty strings, placeholders (runs of X, all one case, no digit or symbol), other attributes whose names merely contain access_key or secret_key, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-008/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["hardcoded-credentials", "secrets", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

_is_tf(path) if endswith(path, ".tofu")

_is_tf(path) if endswith(path, ".tfvars")

_id_re := `^\s*"?(?i:access_key|aws_access_key|aws_access_key_id)"?\s*[=:]\s*"((AKIA|ASIA)[A-Z0-9]{16})"`

_secret_re := `^\s*"?(?i:secret_key|aws_secret_key|aws_secret_access_key)"?\s*[=:]\s*"([A-Za-z0-9/+]{40})"`

_value(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_id_re, line, 1)
	count(m) > 0
}

_value(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_secret_re, line, 1)
	count(m) > 0
	v := m[0][1]
	regex.match(`[a-z]`, v)
	regex.match(`[A-Z]`, v)
	regex.match(`[0-9/+]`, v)
}

# The 40-character secret shape: mixed case plus a digit or symbol.
_secret_shape(v) if {
	regex.match(`^[A-Za-z0-9/+]{40}$`, v)
	regex.match(`[a-z]`, v)
	regex.match(`[A-Z]`, v)
	regex.match(`[0-9/+]`, v)
}

# ECS / container environment entries: { name = "AWS_ACCESS_KEY_ID", value = "..." },
# with the name on the value's line or on one of the two lines above it.
_nv_value(lines, i) := v if {
	m := regex.find_all_string_submatch_n(`\bvalue"?\s*[=:]\s*"([^"]+)"`, lines[i], 1)
	count(m) > 0
	v := m[0][1]
	some j in numbers.range(max([0, i - 2]), i)
	n := regex.find_all_string_submatch_n(`\bname"?\s*[=:]\s*"(?i:(aws_access_key_id|aws_secret_access_key))"`, lines[j], 1)
	count(n) > 0
	_nv_ok(lower(n[0][1]), v)
}

_nv_ok("aws_access_key_id", v) if regex.match(`^(AKIA|ASIA)[A-Z0-9]{16}$`, v)

_nv_ok("aws_secret_access_key", v) if _secret_shape(v)

_found(line, lines, i) := v if v := _value(line)

_found(line, lines, i) := v if {
	not _value(line)
	v := _nv_value(lines, i)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	regex.match(`(?i)(access_key|secret_key)`, content)
	regex.match(`"((AKIA|ASIA)[A-Z0-9]{16}|[A-Za-z0-9/+]{40})"`, content)
	lines := split(content, "\n")
	some i, line in lines
	v := _found(line, lines, i)
	not regex.match(`(?i)x{6}`, v)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded AWS access key in Terraform; remove it, rotate the key, and let the provider read credentials from the environment, a shared credentials profile, an assumed role or OIDC federation",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

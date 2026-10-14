package vulnetix.rules.vnx_sec_003

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-003",
	"name": "AWS secret access key",
	"description": "Reports a hard-coded AWS secret access key: a 40-character base64 value with high entropy assigned to an AWS secret-key name (aws_secret_access_key, AWS_SECRET_ACCESS_KEY, secret_access_key, secretAccessKey, SecretAccessKey, aws_secret_key, aws_secret) in code, config, .env, shell or the ~/.aws/credentials format, the secret_key argument of a Terraform/HCL file that configures AWS, and the second argument of Go's credentials.NewStaticCredentials/NewStaticCredentialsProvider. Not reported: the documented AWS example key (…EXAMPLEKEY) and placeholders, hex digests, environment and CI-secret references, a generic SECRET_KEY outside AWS Terraform, and test, fixture, vendored and generated files. The paired access key ID is VNX-SEC-001.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-003/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "aws", "credentials"],
}

# A name that only AWS uses for the secret half, then the value.
_named := "(?i)(?:^|[^a-z0-9])(?:aws_?secret_?(?:access_?)?key|secret_?access_?key|aws_?secret)[\"']?\\s*(?::=|=>|[:=])\\s*[\"'`]?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|$)"

# Terraform's AWS provider and backends call it secret_key.
_tf_named := `(?:^|[^A-Za-z0-9_])secret_key\s*=\s*"([A-Za-z0-9/+]{40})"`

# Go SDK v1/v2 static credentials: (id, secret, token).
_go_static := `NewStaticCredentials(?:Provider)?\(\s*[^,()]+,\s*"([A-Za-z0-9/+]{40})"`

_tf_ext := [".tf", ".tfvars", ".hcl"]

_is_tf(path) if {
	some e in _tf_ext
	endswith(path, e)
}

_named_tokens(line) := {m[1] |
	regex.match(`(?i)secret_?access|aws_?secret`, line)
	some m in regex.find_all_string_submatch_n(_named, line, -1)
}

_tf_tokens(path, content, line) := {m[1] |
	_is_tf(path)
	contains(line, "secret_key")
	regex.match(`(?i)aws`, content)
	some m in regex.find_all_string_submatch_n(_tf_named, line, -1)
}

_go_tokens(path, line) := {m[1] |
	endswith(path, ".go")
	contains(line, "NewStaticCredentials")
	some m in regex.find_all_string_submatch_n(_go_static, line, -1)
}

# Whole-file gates: the full expression, run once over the file, so the line
# loop only runs where a value of the right shape sits beside the name.
_candidate(_, content) if regex.match(concat("", ["(?m)", _named]), content)

_candidate(path, content) if {
	_is_tf(path)
	regex.match(`secret_key\s*=\s*"[A-Za-z0-9/+]{40}"`, content)
}

_candidate(path, content) if {
	endswith(path, ".go")
	regex.match(_go_static, content)
}

findings contains finding if {
	some path, content in input.file_contents
	_candidate(path, content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)secret_?access_?key|aws_?secret|secret_key|NewStaticCredentials`, line)
	some token in (_named_tokens(line) | _tf_tokens(path, content, line)) | _go_tokens(path, line)
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 4.3)
	finding := {
		"rule_id": metadata.id,
		"message": "AWS secret access key found; deactivate and rotate the key pair in IAM, then load credentials from the environment, an IAM role or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

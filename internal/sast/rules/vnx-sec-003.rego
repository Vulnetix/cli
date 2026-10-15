package vulnetix.rules.vnx_sec_003

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-003",
	"name": "AWS secret access key",
	"description": "Reports a hard-coded AWS secret access key: a 40-character base64 value with high entropy assigned to an AWS secret-key name (aws_secret_access_key, AWS_SECRET_ACCESS_KEY, secret_access_key, secretAccessKey, SecretAccessKey, aws_secret_key, aws_secret) in code, config, .env, shell or the ~/.aws/credentials format, the secret_key argument of a Terraform/HCL file that configures AWS, the second argument of Go's credentials.NewStaticCredentials/NewStaticCredentialsProvider, a quoted 40-character value passed to an SDK credentials constructor on the call line or the next three (Java/.NET BasicAWSCredentials, BasicSessionCredentials, Java v2 AwsBasicCredentials.create, Ruby Aws::Credentials.new, PHP Credentials), and the 'secret' entry of a PHP SDK 'credentials' array. Not reported: the documented AWS example key (…EXAMPLEKEY) and placeholders, hex digests, environment and CI-secret references, a generic SECRET_KEY outside AWS Terraform, and test, fixture, vendored and generated files. The paired access key ID is VNX-SEC-001.",
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

# SDK credential constructors that take (access key id, secret key[, token]):
# Java v1 BasicAWSCredentials/BasicSessionCredentials, Java v2
# AwsBasicCredentials.create, .NET BasicAWSCredentials, Ruby Aws::Credentials.new
# and PHP Aws\Credentials\Credentials. The secret is a quoted 40-character
# value on the call line or on one of the next three lines.
_ctor := `BasicAWSCredentials\(|BasicSessionCredentials\(|Aws(?:Basic|Session)Credentials\.create\(|Aws::Credentials\.new\(|new\s+(?:\\?Aws\\Credentials\\)?Credentials\(`

_quoted40 := "[\"'`]([A-Za-z0-9/+]{40})[\"'`]"

# PHP SDK client config: 'credentials' => ['key' => ..., 'secret' => '...'].
_php_secret := `["']secret["']\s*=>\s*["']([A-Za-z0-9/+]{40})["']`

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

_ctor_tokens(lines, i, line) := {m[1] |
	regex.match(_quoted40, line)
	some j in numbers.range(max([0, i - 3]), i)
	regex.match(_ctor, lines[j])
	some m in regex.find_all_string_submatch_n(_quoted40, line, -1)
}

_php_tokens(path, lines, i, line) := {m[1] |
	endswith(path, ".php")
	contains(line, "secret")
	some j in numbers.range(max([0, i - 4]), i)
	regex.match(`["']credentials["']\s*=>`, lines[j])
	some m in regex.find_all_string_submatch_n(_php_secret, line, -1)
}

# Whole-file gates: the full expression, run once over the file, so the line
# loop only runs where a value of the right shape sits beside the name.
_candidate(_, content) if {
	_has_secret_word(content)
	regex.match(`(?i)secret_?access|aws_?secret`, content)
	regex.match(concat("", ["(?m)", _named]), content)
}

_candidate(path, content) if {
	_is_tf(path)
	contains(content, "secret_key")
	regex.match(`secret_key\s*=\s*"[A-Za-z0-9/+]{40}"`, content)
}

_candidate(_, content) if {
	contains(content, "Credentials")
	regex.match(_ctor, content)
	regex.match(_quoted40, content)
}

_candidate(path, content) if {
	endswith(path, ".php")
	contains(content, "secret")
	regex.match(_php_secret, content)
}

_candidate(path, content) if {
	endswith(path, ".go")
	contains(content, "NewStaticCredentials")
	regex.match(_go_static, content)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not _test_path(path)
	_candidate(path, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match("(?i)secret_?access_?key|aws_?secret|secret_key|NewStaticCredentials|[\"'`][A-Za-z0-9/+]{40}[\"'`]", line)
	tokens := (((_named_tokens(line) | _tf_tokens(path, content, line)) | _go_tokens(path, line)) | _ctor_tokens(lines, i, line)) | _php_tokens(path, lines, i, line)
	some token in tokens
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

_has_secret_word(content) if contains(content, "ecret")

_has_secret_word(content) if contains(content, "ECRET")

# Test code beyond helpers.is_test_path: Jest __mocks__ directories and Xcode
# test targets (AppTests/, FooTests.swift), which hold fake credentials.
_test_path(path) if helpers.is_test_path(path)

_test_path(path) if regex.match(`(^|/)(__mocks__|[A-Za-z0-9_]*Tests)/|Tests?\.swift$`, path)

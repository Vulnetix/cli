package vulnetix.rules.vnx_tf_004

import rego.v1

metadata := {
	"id": "VNX-TF-004",
	"name": "Terraform IAM policy with wildcard Action (*)",
	"description": "An IAM policy statement allows every action: Action = \"*\" or a list containing \"*\" in a jsonencode() policy, \"Action\": \"*\" or [\"*\"] (also spread over several lines) in a heredoc JSON policy, or the escaped form \\\"Action\\\":\\\"*\\\" in a one-line JSON string policy, or actions = [\"*\"] in a data \"aws_iam_policy_document\" statement (or the permissions block of an azurerm_role_definition), whose own effect is Allow or unset (the default). This grants administrator rights over the resources it names, against least privilege. Not reported: a statement whose Effect is Deny (service control and guard policies deny everything on purpose), service-scoped wildcards such as \"s3:*\" or \"ec2:Describe*\", NotAction, principals and resources of \"*\", text in descriptions, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-tf-004/",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [269],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1078"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["iam", "least-privilege", "aws", "terraform"],
}

_is_tf(path) if endswith(path, ".tf")

_is_tf(path) if endswith(path, ".tofu")

_is_comment(line) if regex.match(`^\s*(#|//|/\*|\*)`, line)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_key := `("Action"|\bAction|^\s*actions)`

# The action list on line i contains "*" on the same line.
_wild(lines, i) if regex.match(sprintf(`%s\s*[=:]\s*(\[[^\]]*)?"\*"`, [_key]), lines[i])

# A JSON policy written as one escaped string literal.
_wild(lines, i) if regex.match(`\\"Action\\"\s*:\s*(\[[^\]]*)?\\"\*\\"`, lines[i])

# The action list opens on line i and "*" is one of its continuation lines.
_wild(lines, i) if {
	regex.match(sprintf(`%s\s*[=:]\s*\[\s*$`, [_key]), lines[i])
	ends := [j | some j in numbers.range(i + 1, min([count(lines) - 1, i + 30])); contains(lines[j], "]")]
	count(ends) > 0
	some j in numbers.range(i + 1, min(ends))
	regex.match(`^\s*"\*"\s*,?\s*$`, lines[j])
}

# The statement opened by the nearest less-indented line ending in "{".
_stmt_start(lines, i) := max(ks) if {
	ind := _indent(lines[i])
	ks := [k |
		some k in numbers.range(max([0, i - 40]), i - 1)
		regex.match(`\{\s*$`, lines[k])
		_indent(lines[k]) < ind
		not _is_comment(lines[k])
	]
	count(ks) > 0
}

_stmt_end(lines, k) := min(array.concat([min([count(lines) - 1, k + 60])], [j |
	some j in numbers.range(k + 1, min([count(lines) - 1, k + 60]))
	regex.match(`^\s*\}`, lines[j])
	_indent(lines[j]) <= _indent(lines[k])
]))

_effect_re := `(?i)\\?"?\beffect\\?"?\s*[=:]\s*\\?"`

_deny_re := `(?i)\\?"?\beffect\\?"?\s*[=:]\s*\\?"deny\\?"`

# A one-line statement carries its own effect.
_denied(lines, i) if {
	regex.match(_effect_re, lines[i])
	regex.match(_deny_re, lines[i])
}

_denied(lines, i) if {
	not regex.match(_effect_re, lines[i])
	k := _stmt_start(lines, i)
	some j in numbers.range(k, _stmt_end(lines, k))
	not _is_comment(lines[j])
	regex.match(_deny_re, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	regex.match(`\\?"\*\\?"`, content)
	regex.match(`(Action|actions)\\?"?\s*[=:]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(Action|actions)\\?"?\s*[=:]`, line)
	not _is_comment(line)
	_wild(lines, i)
	not _denied(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "IAM policy statement allows Action \"*\" (every action); list only the specific actions this principal needs, or use a service-scoped set such as an AWS managed job-function policy",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

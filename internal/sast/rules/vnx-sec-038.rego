package vulnetix.rules.vnx_sec_038

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-038",
	"name": "HashiCorp Terraform Cloud token",
	"description": "Reports a Terraform Cloud / Terraform Enterprise API token: a standalone token of 14 letters and digits, .atlasv1., and 60 or more base64url characters, in any file including .tfvars and .terraformrc. Placeholders and test or fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-038/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "terraform", "hashicorp", "credentials"],
}

_pattern := `\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,})`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, ".atlasv1.")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".atlasv1.")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(token)
	finding := {
		"rule_id": metadata.id,
		"message": "Terraform Cloud API token found; revoke it in Terraform Cloud (User or Team settings > Tokens) and rotate any secrets its workspaces expose",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

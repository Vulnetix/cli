package vulnetix.rules.vnx_sec_079

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-079",
	"name": "GitHub fine-grained personal access token",
	"description": "Reports a GitHub fine-grained personal access token (github_pat_, 22 alphanumeric characters, an underscore and 59 more) as a whole token in any file: standalone, assigned, in an Authorization header or inside a clone URL. Not reported: the bare prefix, truncated tokens, placeholder or low-entropy bodies (github_pat_xxxx...), environment and CI-secret references, and test, fixture, vendored and generated files. VNX-SEC-004 reports the same token as part of its wider GitHub/GitLab set.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-079/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "github", "credentials"],
}

_pattern := `(?:^|[^A-Za-z0-9_])github_pat_([A-Za-z0-9]{22}_[A-Za-z0-9]{59})(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "github_pat_")
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "github_pat_")
	some m in regex.find_all_string_submatch_n(_pattern, line, -1)
	not secrets.is_example_token(m[1])
	secrets.high_entropy(m[1], 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "GitHub fine-grained personal access token found; revoke it in GitHub (Settings > Developer settings > Fine-grained tokens) and pass the replacement through a CI secret",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

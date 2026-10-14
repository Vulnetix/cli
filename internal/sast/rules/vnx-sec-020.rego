package vulnetix.rules.vnx_sec_020

import rego.v1

import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-020",
	"name": "GitLab access token",
	"description": "Reports a GitLab token written into a file: a personal, project or group access token (glpat- followed by 20 or more token characters, including the newer routable form with a .01. segment), a deploy token (gldt-), a runner authentication token (glrt-), a CI/CD job token (glcbt-), an OAuth application secret (gloas-) or a pipeline trigger token (glptt- followed by 40 hex characters). The token must stand alone (not the tail of a longer identifier), must not be a placeholder (xxxx, your-token, EXAMPLE) and must have the entropy of a real token; the snippet is redacted. Not reported: tokens read from CI variables or the environment ($GITLAB_TOKEN, ${CI_JOB_TOKEN}), the bare prefix in validation code, and test, fixture, vendored and generated paths. Overlaps VNX-SEC-004 and VNX-SEC-039 on glpat- tokens.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-020/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "gitlab", "credentials"],
}

_token_re := `(?:^|[^\w-])((?:glpat|gldt|glrt|glcbt|gloas)-[A-Za-z0-9_-]{20,}(?:\.[0-9a-z]{2}\.[A-Za-z0-9_-]{6,})?|glptt-[0-9a-f]{40})(?:[^\w-]|$)`

_tokens(line) := {tok |
	some m in regex.find_all_string_submatch_n(_token_re, line, -1)
	tok := m[1]
	not secrets.is_example_token(tok)
	secrets.high_entropy(tok, 3.5)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	regex.match(`gl(?:pat|dt|rt|cbt|oas|ptt)-[A-Za-z0-9_-]{20}`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`gl(?:pat|dt|rt|cbt|oas|ptt)-`, line)
	count(_tokens(line)) > 0
	finding := {
		"rule_id": metadata.id,
		"message": "GitLab token found; revoke it in GitLab, then load it from a masked CI/CD variable, the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

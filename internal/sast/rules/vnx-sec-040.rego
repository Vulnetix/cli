package vulnetix.rules.vnx_sec_040

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-040",
	"name": "GitLab pipeline trigger / deploy / runner token",
	"description": "Reports a GitLab infrastructure token by its documented prefix and body shape: pipeline trigger (glptt- + 40 hex), deploy (gldt-), runner authentication (glrt-), runner registration (GR1348941), Kubernetes agent (glagent-), CI job (glcbt-), OAuth application secret (gloas-), incoming mail (glimt-), feature-flag client (glffct-), feed (glft-) and SCIM (glsoat-) tokens. A prefix without a token body of the right length, placeholders and test or fixture paths are not reported; glpat- access tokens are VNX-SEC-039.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-040/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "gitlab", "ci", "credentials"],
}

_tokens := [
	["pipeline trigger", "glptt-", `\b(glptt-[0-9a-f]{40})\b`],
	["deploy", "gldt-", `\b(gldt-[0-9A-Za-z_-]{20,})`],
	["runner authentication", "glrt-", `\b(glrt-[0-9A-Za-z_-]{20,})`],
	["runner registration", "GR1348941", `\b(GR1348941[0-9A-Za-z_-]{20,})`],
	["Kubernetes agent", "glagent-", `\b(glagent-[0-9A-Za-z_-]{50,})`],
	["CI job", "glcbt-", `\b(glcbt-[0-9A-Za-z]{1,5}_[0-9A-Za-z_-]{20,})`],
	["OAuth application secret", "gloas-", `\b(gloas-[0-9A-Za-z_-]{64})\b`],
	["incoming mail", "glimt-", `\b(glimt-[0-9A-Za-z_-]{25})\b`],
	["feature-flag client", "glffct-", `\b(glffct-[0-9A-Za-z_-]{20,})`],
	["feed", "glft-", `\b(glft-[0-9A-Za-z_-]{20,})`],
	["SCIM", "glsoat-", `\b(glsoat-[0-9A-Za-z_-]{20,})`],
]

# A token body is random base64url; "glft-icon-container-wrapper" is a CSS class.
_wordlike(tok) if regex.match(`^(?:gl[a-z]+-|GR1348941)[a-z_-]+$`, tok)

_gate(content) if {
	some t in _tokens
	contains(content, t[1])
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	some t in _tokens
	contains(line, t[1])
	m := regex.find_all_string_submatch_n(t[2], line, 1)
	count(m) > 0
	token := m[0][1]
	not _wordlike(token)
	not secrets.is_example_token(token)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GitLab %s token found; revoke it in GitLab and load it from a masked CI/CD variable", [t[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

package vulnetix.rules.vnx_sec_080

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-080",
	"name": "GitHub OAuth / App / Refresh token",
	"description": "Reports a GitHub OAuth access token (gho_), GitHub App user-to-server token (ghu_), App installation (server-to-server) token (ghs_) or refresh token (ghr_, 36 or 76 characters) as a whole token in any file: quoted, assigned, in an Authorization header or inside a clone URL (https://x-access-token:ghs_...@github.com). Not reported: classic personal access tokens (ghp_) and fine-grained tokens (github_pat_), which VNX-SEC-004 and VNX-SEC-079 report, bare prefixes and prefix checks, truncated tokens, placeholder or low-entropy bodies, environment and CI-secret references, and test, fixture, Jest __mocks__, vendored and generated files. VNX-SEC-004 also reports these tokens as part of its wider set.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-080/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "github", "oauth", "credentials"],
}

_kinds := {
	"gho": "GitHub OAuth token found; revoke the OAuth app authorisation in GitHub settings and load the token from the environment",
	"ghu": "GitHub App user-to-server token found; revoke the app authorisation in GitHub settings and load the token from the environment",
	"ghs": "GitHub App installation token found; regenerate it from the app's private key at runtime instead of committing it",
	"ghr": "GitHub refresh token found; revoke the OAuth/App authorisation in GitHub settings and store refresh tokens in a secrets manager",
}

_pattern := `(?:^|[^A-Za-z0-9_])(gh[ousr])_([A-Za-z0-9]{36}|[A-Za-z0-9]{76})(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`gh[ousr]_[A-Za-z0-9]{36}`, content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not contains(concat("", ["/", path]), "/__mocks__/")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`gh[ousr]_`, line)
	some m in regex.find_all_string_submatch_n(_pattern, line, -1)
	m[1] != "ghp"
	not secrets.is_example_token(m[2])
	secrets.high_entropy(m[2], 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": _kinds[m[1]],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

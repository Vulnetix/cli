package vulnetix.rules.vnx_sec_070

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-070",
	"name": "1Password secret key / service account",
	"description": "Reports a 1Password credential in any file: a service account token (ops_eyJ followed by at least 50 base64url characters, the form OP_SERVICE_ACCOUNT_TOKEN holds) or an account Secret Key (A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX, and the older A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX layout, uppercase letters and digits, both present).The credential is masked in the snippet. Not reported: the bare ops_eyJ / ops_ prefix in token checks, truncated examples (ops_eyJ...), CI secret references (${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}), A3- strings of a different layout or with an all-digit body (paper sizes, SKUs, batch numbers), placeholder runs (A3-XXXXXX-...), and generated, vendored and test-suffixed files and testdata/fixtures directories.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-070/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "1password", "credentials"],
}

_ops := `\b(ops_eyJ[A-Za-z0-9_\-+/]{50,}={0,2})`

_secret_key := `(?:^|[^A-Za-z0-9-])(A3-[A-Z0-9]{6}-(?:[A-Z0-9]{6}-[A-Z0-9]{5}|[A-Z0-9]{11})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})(?:[^A-Za-z0-9-]|$)`

_tokens(line) := _ops_tokens(line) | _secret_keys(line)

_ops_tokens(line) := {m[1] |
	contains(line, "ops_eyJ")
	some m in regex.find_all_string_submatch_n(_ops, line, -1)
	not secrets.is_placeholder(m[1])
}

_secret_keys(line) := {m[1] |
	contains(line, "A3-")
	some m in regex.find_all_string_submatch_n(_secret_key, line, -1)
	regex.match(`[0-9]`, m[1])
	# A real Secret Key mixes letters and digits; an all-digit body is a part
	# or batch number.
	regex.match(`[A-Z]`, substring(m[1], 3, -1))
	not secrets.is_placeholder(m[1])
}

_candidate(content) if contains(content, "ops_eyJ")

_candidate(content) if {
	contains(content, "A3-")
	regex.match(`A3-[A-Z0-9]{6}-`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	_candidate(content)
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`ops_eyJ|A3-`, line)
	some tok in _tokens(line)
	finding := {
		"rule_id": metadata.id,
		"message": "1Password credential found; revoke the service account token or regenerate the account Secret Key in 1Password, and read it from the environment at runtime",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, tok, "***"),
	}
}

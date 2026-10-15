package vulnetix.rules.vnx_sec_019

import rego.v1

import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-019",
	"name": "GCP service account key",
	"description": "Reports a Google Cloud service account key committed to a file: the \"private_key\" member carrying a PEM private key (-----BEGIN PRIVATE KEY----- or RSA PRIVATE KEY with a real base64 body) in a document that also declares \"type\": \"service_account\" within 20 lines. Both the plain JSON key file and the same document embedded as an escaped string (\\\"private_key\\\": ...) in an environment file, Terraform, YAML or source code are reported, as are the YAML form with the key inline (type: service_account, private_key: \"-----BEGIN ...\") or in a private_key: | block scalar, and the TOML form of .streamlit/secrets.toml (type = \"service_account\", private_key = \"-----BEGIN ...\"). The snippet is redacted. Not reported: a file that only names the type (google-auth and client libraries compare against the string \"service_account\"), a key file with an empty or placeholder private_key, and test, fixture, vendored and generated paths. Overlaps the generated rules VNX-SEC-148 (private_key_id) and VNX-SEC-174 (PEM in JSON).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-019/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "gcp", "google-cloud", "service-account"],
}

# "type": "service_account", escaped or not, the YAML form, or the TOML
# form (type = "service_account", as in .streamlit/secrets.toml).
_type_re := `\\?["']?type\\?["']?\s*[:=]\s*\\?["']?service_account\b`

# The private_key member and the PEM body (escaped \n or real newlines are
# both base64-free characters, so the body is measured in base64 runs).
_key_re := `\\?["']?private_key\\?["']?\s*[:=]\s*\\?["']?-----BEGIN (?:RSA )?PRIVATE KEY-----((?:\\n|\\\\n|[A-Za-z0-9+/=\s])*)`

# A YAML block scalar: private_key: | with the PEM on the following lines.
_block_re := `^\s*["']?private_key["']?\s*:\s*[|>][-+]?\s*$`

_body(lines, i) := b if {
	m := regex.find_all_string_submatch_n(_key_re, lines[i], 1)
	count(m) > 0
	b := m[0][1]
}

# A YAML block or a PEM written over real lines: the body follows the line.
_full_body(lines, i) := b if {
	b0 := _body(lines, i)
	nxt := [l | some k in numbers.range(i + 1, min([count(lines) - 1, i + 3])); l := lines[k]]
	b := concat("", array.concat([b0], nxt))
}

_full_body(lines, i) := b if {
	regex.match(_block_re, lines[i])
	i + 1 < count(lines)
	regex.match(`^\s*-----BEGIN (?:RSA )?PRIVATE KEY-----\s*$`, lines[i + 1])
	b := concat("", [l | some k in numbers.range(i + 2, min([count(lines) - 1, i + 4])); l := lines[k]])
}

_body_b64(b) := regex.replace(regex.replace(b, `\\\\n|\\n`, ""), `[^A-Za-z0-9+/=]`, "")

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	contains(content, "service_account")
	contains(content, "PRIVATE KEY-----")
	regex.match(_type_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "private_key")
	b64 := _body_b64(_full_body(lines, i))
	count(b64) >= 100
	not secrets.is_placeholder(substring(b64, 0, 60))
	secrets.high_entropy(b64, 4.5)
	some j in numbers.range(max([0, i - 20]), min([count(lines) - 1, i + 20]))
	regex.match(_type_re, lines[j])
	finding := {
		"rule_id": metadata.id,
		"message": "GCP service account private key committed; disable the key in IAM, then use workload identity federation or load the key from a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

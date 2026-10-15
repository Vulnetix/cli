package vulnetix.rules.vnx_sec_078

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-078",
	"name": "Doppler API token",
	"description": "Reports a Doppler personal token (dp.pt. followed by 43 mixed-case alphanumeric characters) as a whole token in any file: quoted, assigned (DOPPLER_TOKEN=...), passed to doppler --token or in an Authorization header. Not reported: service, CLI, service-account and audit tokens (dp.st., dp.ct., dp.sa., dp.audit.), which VNX-SEC-1022 to VNX-SEC-1025 report, the bare prefix, truncated tokens, placeholder or low-entropy bodies, environment references, and test, fixture, vendored and generated files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-078/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "doppler", "credentials"],
}

# The body is mixed case; the original rule allowed only lower case and
# could not match a real token.
_pattern := `(?:^|[^A-Za-z0-9_.])(dp\.pt\.([A-Za-z0-9]{43}))(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "dp.pt.")
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "dp.pt.")
	some m in regex.find_all_string_submatch_n(_pattern, line, -1)
	not secrets.is_example_token(m[2])
	secrets.high_entropy(m[2], 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": "Doppler personal token found; revoke it in the Doppler dashboard (Tokens) and use a scoped service token from a CI secret instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

package vulnetix.rules.vnx_sec_032

import rego.v1

metadata := {
	"id": "VNX-SEC-032",
	"name": "PGP private key block hardcoded",
	"description": "A PGP/GPG private key block is present in source code. Private keys committed to version control are permanently exposed in history even if subsequently removed. This key should be revoked on keyservers immediately, a new key pair generated, and the private key stored only in a secrets manager or secure keyring.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-032/",
	"languages": ["generic"],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [321],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secret", "pgp", "private-key", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "-----BEGIN PGP PRIVATE KEY BLOCK-----")
	finding := {
		"rule_id": metadata.id,
		"message": "PGP private key block detected in source — revoke on keyservers, generate a new key pair, and never commit private keys",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

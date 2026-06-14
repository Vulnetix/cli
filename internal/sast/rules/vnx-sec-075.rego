package vulnetix.rules.vnx_sec_075

import rego.v1

metadata := {
	"id": "VNX-SEC-075",
	"name": "WireGuard private key",
	"description": "A WireGuard interface private key (base64 44-char or hex 64-char value assigned to PrivateKey) was found in source code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-075/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "wireguard", "vpn", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".md")
_skip(path) if endswith(path, ".conf.example")
_skip(path) if endswith(path, ".sample")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(?i)privatekey\s*=\s*[A-Za-z0-9+/]{42,44}={0,2}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "WireGuard private key found; regenerate the keypair and update the peer configuration",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

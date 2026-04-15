package vulnetix.rules.vnx_py_021

import rego.v1

metadata := {
	"id": "VNX-PY-021",
	"name": "Weak or deprecated SSL/TLS protocol version",
	"description": "The code references a deprecated SSL/TLS protocol constant (SSLv2, SSLv3, TLSv1, TLSv1.1) that is known to be vulnerable. These versions have documented cryptographic weaknesses and are rejected by modern servers. Use ssl.PROTOCOL_TLS_CLIENT with a minimum version of TLSv1.2 or higher.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-021/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [326],
	"capec": ["CAPEC-217"],
	"attack_technique": ["T1040"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["ssl", "tls", "cryptography", "python"],
}

_is_py(path) if endswith(path, ".py")

_weak_ssl_patterns := [
	"PROTOCOL_SSLv2",
	"PROTOCOL_SSLv3",
	"PROTOCOL_TLSv1",
	"PROTOCOL_TLSv1_1",
	"SSLv2_METHOD",
	"SSLv3_METHOD",
	"TLSv1_METHOD",
	"TLSv1_1_METHOD",
]

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some pattern in _weak_ssl_patterns
	contains(line, pattern)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak or deprecated SSL/TLS version constant '%v' detected; use ssl.PROTOCOL_TLS_CLIENT with ssl.TLSVersion.TLSv1_2 or higher", [pattern]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

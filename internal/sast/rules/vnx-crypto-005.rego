package vulnetix.rules.vnx_crypto_005

import rego.v1

metadata := {
	"id": "VNX-CRYPTO-005",
	"name": "TLS certificate validation disabled",
	"description": "TLS certificate verification is disabled, allowing man-in-the-middle attacks. Never disable certificate validation in production.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-005/",
	"languages": ["python", "node", "go", "java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["tls", "certificate", "mitm", "transport-security"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_tls_bypass_indicators := {
	"verify=False",
	"verify = False",
	"InsecureSkipVerify: true",
	"InsecureSkipVerify:true",
	"NODE_TLS_REJECT_UNAUTHORIZED",
	"rejectUnauthorized: false",
	"rejectUnauthorized:false",
	"CERT_NONE",
	"check_hostname = False",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _tls_bypass_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("TLS certificate validation disabled (%s); enable certificate verification", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

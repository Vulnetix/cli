package vulnetix.rules.vnx_java_006

import rego.v1

metadata := {
	"id": "VNX-JAVA-006",
	"name": "Insecure TLS trust manager",
	"description": "An X509TrustManager with an empty checkServerTrusted() method or a HostnameVerifier that always returns true disables TLS validation, enabling man-in-the-middle attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-006/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["tls", "certificate", "mitm", "trust-manager"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_trust_bypass_indicators := {
	"ALLOW_ALL_HOSTNAME_VERIFIER",
	"TrustAllCerts",
	"trustAllCerts",
	"NullTrustManager",
	"AcceptAllTrustManager",
	"TrustAll",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _trust_bypass_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Insecure TLS configuration (%s); implement proper certificate validation", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`checkServerTrusted.*\{\s*\}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Empty checkServerTrusted() disables certificate validation; implement proper trust verification",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_java_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-006",
	"name": "Insecure TLS trust manager",
	"description": "Reports Java code that switches off TLS server authentication: an X509TrustManager whose checkServerTrusted() body is empty (or only returns, or only holds comments), a HostnameVerifier whose verify(String, SSLSession) just returns true, an Apache TrustStrategy whose isTrusted() returns true, a (hostname, session) -> true lambda passed to setHostnameVerifier/setDefaultHostnameVerifier/hostnameVerifier or assigned to a HostnameVerifier, a loadTrustMaterial lambda returning true, and the trust-everything constants NoopHostnameVerifier, ALLOW_ALL_HOSTNAME_VERIFIER/AllowAllHostnameVerifier, TrustAllStrategy, TrustSelfSignedStrategy and Netty InsecureTrustManagerFactory.INSTANCE. Any certificate or host name is then accepted, enabling man-in-the-middle attacks. Not reported: class or variable names that merely say trust-all, a checkServerTrusted that delegates or throws, an empty checkClientTrusted, imports, comments, string literals, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-006/",
	"languages": ["java"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["tls", "certificate", "mitm", "trust-manager"],
}

_gate := `checkServerTrusted|HostnameVerifier|hostnameVerifier|isTrusted|TrustAllStrategy|TrustSelfSignedStrategy|loadTrustMaterial|InsecureTrustManagerFactory|ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|SSLSession`

# Code only: string literals emptied, trailing and inline comments removed.
_code(line) := regex.replace(regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `/\*.*?\*/`, " "), `//.*$`, "")

_block(lines, i) := concat(" ", [_code(lines[k]) |
	some k in numbers.range(i, min([count(lines) - 1, i + 8]))
	not regex.match(`^\s*\*`, lines[k])
])

_single := [
	`\bNoopHostnameVerifier\b`,
	`\bALLOW_ALL_HOSTNAME_VERIFIER\b`,
	`\bnew\s+AllowAllHostnameVerifier\s*\(`,
	`\b(?:TrustAllStrategy|TrustSelfSignedStrategy)\b`,
	`\bInsecureTrustManagerFactory\.INSTANCE\b`,
	`(?i)hostnameVerifier\s*\(\s*\(\s*\w*\s*,\s*\w*\s*\)\s*->\s*(?:true\b|\{\s*return\s+true\s*;)`,
	`\bHostnameVerifier\s+\w+\s*=\s*\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*(?:true\b|\{\s*return\s+true\s*;)`,
	`\bloadTrustMaterial\s*\([^;]*\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*(?:true\b|\{\s*return\s+true\s*;)`,
]

# Method declarations whose whole body trusts everything.
_bodies := [
	[`\bvoid\s+checkServerTrusted\s*\(`, `\bvoid\s+checkServerTrusted\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*(?:return\s*;\s*)?\}`],
	[`\bboolean\s+verify\s*\(`, `\bboolean\s+verify\s*\(\s*(?:final\s+)?String\s+\w+\s*,\s*(?:final\s+)?(?:javax\.net\.ssl\.)?SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;\s*\}`],
	[`\bboolean\s+isTrusted\s*\(`, `\bboolean\s+isTrusted\s*\([^)]*X509Certificate[^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*return\s+true\s*;\s*\}`],
]

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*import\s`, line)
	_hit(lines, i, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": "TLS certificate or host-name verification is disabled, so any server certificate is accepted; use the default TrustManager/HostnameVerifier or trust a private CA explicitly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_hit(_, _, code) if {
	some re in _single
	regex.match(re, code)
}

_hit(lines, i, code) if {
	some pair in _bodies
	regex.match(pair[0], code)
	regex.match(pair[1], _block(lines, i))
}

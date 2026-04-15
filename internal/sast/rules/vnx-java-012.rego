package vulnetix.rules.vnx_java_012

import rego.v1

metadata := {
	"id": "VNX-JAVA-012",
	"name": "Java LDAP injection",
	"description": "Constructing LDAP search filters from user input without sanitization enables LDAP injection, allowing attackers to bypass authentication or exfiltrate directory data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-012/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [90],
	"capec": ["CAPEC-136"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ldap", "injection", "authentication"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_ldap_indicators := {
	"ctx.search(request.getParameter",
	"ctx.search(req.getParameter",
	"dirContext.search(request.getParameter",
	"DirContext.search(request.getParameter",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _ldap_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input in LDAP query; use parameterized LDAP filters or sanitize special characters",
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
	regex.match(`"\(.*="\s*\+\s*request\.getParameter`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User input in LDAP query; use parameterized LDAP filters or sanitize special characters",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

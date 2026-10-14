# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_757

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-757",
	"name": "CWE-757",
	"description": "Detects source patterns associated with CWE-757 (CWE-757). Each finding should be manually reviewed for exploitability in context.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-757/",
	"languages": ["go", "java", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [757],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "downgrade", "cwe-757"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")
_skip(path) if endswith(path, ".min.html")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")
_is_comment_line(line) if startswith(trim_space(line), "--")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".py", ".java", ".go"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	not helpers.is_test_path(path)
	some _pat, re in _obsolete
	regex.match(re, line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Obsolete TLS/cipher %s — enforce TLS 1.2+ with modern ciphersuites", [_pat]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Version tokens, not substrings: "TLSv1" is inside "TLSv1.2" and "TLSv1_3", which
# are the versions this rule asks for. A bare TLSv1 is the 1.0 protocol; a dot or
# underscore after it continues the name of another version.
_obsolete := {
	"SSLv2": `\bSSLv2\b`,
	"SSLv3": `\bSSLv3\b`,
	"TLSv1": `\bTLSv1([^.\w]|$)`,
	"TLSv1.0": `\bTLSv1[._]0\b`,
	"TLSv1.1": `\bTLSv1[._]1\b`,
	"tls.VersionTLS10/11": `\bVersionTLS1[01]\b`,
	"tls.VersionSSL30": `\bVersionSSL30\b`,
	"TLS_RSA_": `\bTLS_RSA_\w+`,
}

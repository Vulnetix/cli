package vulnetix.rules.vnx_go_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-004",
	"name": "TLS InsecureSkipVerify enabled",
	"description": "A crypto/tls Config turns off certificate verification with the constant true: InsecureSkipVerify: true in a struct literal (http.Transport, gRPC credentials.NewTLS, database and broker clients) or an assignment x.InsecureSkipVerify = true, so any certificate, for any host, is accepted and the connection can be intercepted. A switch that is not about certificates (if debug {) does not make it safe and is reported. Not reported: InsecureSkipVerify set from a variable, flag or environment value (the operator's explicit choice) or false; true set inside an if whose condition names the insecure/skip-verify option (--insecure, like curl -k); a config that replaces the default check with its own VerifyPeerCertificate or VerifyConnection callback within a few lines (certificate pinning, private roots); the field declaration of an options struct; the text inside a string literal or comment; and _test.go/testdata code, where httptest servers use throwaway certificates.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-004/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["tls", "certificate", "mitm", "transport-security"],
}

_set_true := `InsecureSkipVerify\s*:\s*true\b|\.InsecureSkipVerify\s*=\s*true\b`

# The match starts outside a string literal: an even number of double quotes
# and no raw-string backtick before it on the line.
_in_code(line) if {
	idx := indexof(line, "InsecureSkipVerify")
	prefix := regex.replace(substring(line, 0, idx), `\\.`, "")
	not contains(prefix, "`")
	count(regex.find_all_string_submatch_n(`"`, prefix, -1)) % 2 == 0
}

# The default check is replaced by the program's own verification callback.
_custom_verify(lines, i) if {
	w := helpers.code_window(lines, i, 12, 12)
	regex.match(`\bVerify(?:PeerCertificate|Connection)\s*(?::|=)\s*[^n\s]`, w)
}

# Inside an if whose condition is the insecure option itself.
_opted_in(lines, i) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	l := lines[k]
	regex.match(`^\s*(?:\}\s*else\s+)?if\b.*\{\s*$`, l)
	regex.match(`(?i)insecure|skip_?verify|no_?verify|tls_?verify|self_?signed|allow_?untrusted|ignore_?cert|accept_?any`, l)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "InsecureSkipVerify")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "InsecureSkipVerify")
	regex.match(_set_true, line)
	not helpers.is_comment_line(line)
	_in_code(line)
	not _custom_verify(lines, i)
	not _opted_in(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "InsecureSkipVerify: true disables TLS certificate verification; trust the CA through RootCAs (or verify a pin in VerifyPeerCertificate) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

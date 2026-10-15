package vulnetix.rules.vnx_go_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-004",
	"name": "TLS InsecureSkipVerify enabled",
	"description": "A crypto/tls Config turns off certificate verification with the constant true: InsecureSkipVerify: true in a struct literal (http.Transport, gRPC credentials.NewTLS, database and broker clients) or an assignment x.InsecureSkipVerify = true, so any certificate, for any host, is accepted and the connection can be intercepted. A switch that is not about certificates (if debug {) does not make it safe and is reported. Not reported: InsecureSkipVerify set from a variable, flag or environment value (the operator's explicit choice) or false; true set inside an if whose condition names the insecure/skip-verify option (--insecure, like curl -k) and whose block is still open; a config that replaces the default check with its own VerifyPeerCertificate or VerifyConnection callback within a few lines and in the same config (no other tls.Config or function declaration between them); the field declaration of an options struct; the text inside a string literal (including a multi-line raw string) or comment; and _test.go/testdata code and test-support packages (httptest, acmetest, testutil, testing, testenv), where test servers use throwaway certificates.",
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

# The default check is replaced by the program's own verification callback,
# in the same config: no other tls.Config, InsecureSkipVerify or top-level
# func declaration lies between the two lines.
_verify_re := `\bVerify(?:PeerCertificate|Connection)\s*(?::|=)\s*[^n\s]`

_boundary := `tls\.Config\s*\{|InsecureSkipVerify|^func\s`

_custom_verify(lines, i) if {
	some k in numbers.range(i, min([count(lines) - 1, i + 12]))
	regex.match(_verify_re, lines[k])
	not helpers.is_comment_line(lines[k])
	not _crossed(lines, i + 1, k - 1)
}

_custom_verify(lines, i) if {
	some k in numbers.range(max([0, i - 12]), i - 1)
	regex.match(_verify_re, lines[k])
	not helpers.is_comment_line(lines[k])
	not _crossed(lines, k + 1, i - 1)
}

_crossed(lines, a, b) if {
	a <= b
	some m in numbers.range(a, b)
	regex.match(_boundary, lines[m])
}

# Inside an if whose condition is the insecure option itself, and whose block
# has not closed before the line.
_opted_in(lines, i) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	l := lines[k]
	regex.match(`^\s*(?:\}\s*else\s+)?if\b.*\{\s*$`, l)
	regex.match(`(?i)insecure|skip_?verify|no_?verify|tls_?verify|self_?signed|allow_?untrusted|ignore_?cert|accept_?any`, l)
	not _closed(lines, k + 1, i - 1)
}

_closed(lines, a, b) if {
	a <= b
	some m in numbers.range(a, b)
	startswith(trim_space(lines[m]), "}")
}

# Test-support packages (httptest, acmetest, testutil, testing) serve and
# dial throwaway certificates by design.
_test_support(path) if regex.match(`(?:^|/)(?:(?:http|acme|net|grpc|tls|e2e|integration|int)test|\w*testing|testutils?|testhelpers?|testenv|testserver)/[^/]+\.go$`, path)

# The line lies inside a raw string literal opened on an earlier line.
_in_raw_string(lines, i) if {
	ticks := sum([count(indexof_n(lines[m], "`")) | some m in numbers.range(max([0, i - 60]), i - 1)])
	ticks % 2 == 1
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "InsecureSkipVerify")
	not helpers.is_test_path(path)
	not _test_support(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "InsecureSkipVerify")
	regex.match(_set_true, line)
	not helpers.is_comment_line(line)
	_in_code(line)
	not _in_raw_string(lines, i)
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

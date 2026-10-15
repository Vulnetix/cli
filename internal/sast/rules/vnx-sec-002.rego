package vulnetix.rules.vnx_sec_002

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-002",
	"name": "Private key committed",
	"description": "Reports a committed PEM private key: a -----BEGIN RSA/EC/DSA/OPENSSH PRIVATE KEY----- or PKCS#8 -----BEGIN PRIVATE KEY----- armour line that is followed by real key material, either base64 on the same line (an escaped \\n string in code, JSON or Terraform) or a base64 line within the next four lines (a key file, heredoc, YAML block or multi-line string, including legacy Proc-Type encrypted PEM). Not reported: code that only builds, strips or compares the armour, placeholder bodies, public keys and certificates, examples in Markdown/reStructuredText/AsciiDoc or in comments, and test, fixture, vendored and generated files. PKCS#8 ENCRYPTED PRIVATE KEY blocks are VNX-SEC-646.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-002/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [321],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "private-key", "cryptography"],
}

_header := `-----BEGIN ((?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----`

_doc_ext := [".md", ".markdown", ".rst", ".adoc", ".asciidoc"]

_is_doc(path) if {
	some e in _doc_ext
	endswith(lower(path), e)
}

# Key material on the header line itself: an escaped newline (or whitespace)
# then a base64 run, as in "-----BEGIN RSA PRIVATE KEY-----\nMIIC...".
_inline_body(line) := b if {
	m := regex.find_all_string_submatch_n(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?(?:\\[rn]|\s)([A-Za-z0-9+/]{40,})`, line, 1)
	count(m) > 0
	b := m[0][1]
}

# Key material on one of the next four lines: a line that is only base64
# (after indentation, a YAML/heredoc margin, a quote or a concatenation).
_next_body(lines, i) := b if {
	i + 1 < count(lines)
	bodies := [m[0][1] |
		some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
		m := regex.find_all_string_submatch_n(`^\s*[|"'+]?\s*([A-Za-z0-9+/]{40,})={0,2}(?:\\n)?["',;+\s\\]*$`, lines[j], 1)
		count(m) > 0
	]
	count(bodies) > 0
	b := bodies[0]
}

_body(lines, i, line) := b if {
	b := _inline_body(line)
} else := b if {
	b := _next_body(lines, i)
}

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "PRIVATE KEY-----")
	not secrets.skip_path(path)
	not _test_path(path)
	not _is_doc(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "PRIVATE KEY-----")
	m := regex.find_all_string_submatch_n(_header, line, 1)
	count(m) > 0
	not _is_comment(line)
	body := _body(lines, i, line)
	not secrets.is_placeholder(body)
	secrets.high_entropy(body, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s committed; remove it from the repository and its history, revoke and replace the key, and load it from a secrets manager at runtime", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

# helpers.is_comment_line treats a leading "--" as a SQL comment, which is
# every PEM armour line; test the comment syntaxes a key example sits in.
_is_comment(line) if regex.match(`^\s*(?://|/\*|\*|#)`, line)

# Test code beyond helpers.is_test_path: Jest __mocks__ directories and Xcode
# test targets (AppTests/, FooTests.swift), which hold fake credentials.
_test_path(path) if helpers.is_test_path(path)

_test_path(path) if regex.match(`(^|/)(__mocks__|[A-Za-z0-9_]*Tests)/|Tests?\.swift$`, path)

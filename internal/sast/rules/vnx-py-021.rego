package vulnetix.rules.vnx_py_021

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-021",
	"name": "Weak or deprecated SSL/TLS protocol version",
	"description": "A Python TLS context is made to use or allow SSLv2, SSLv3, TLS 1.0 or TLS 1.1. Reported, in code: the ssl constants PROTOCOL_SSLv2, PROTOCOL_SSLv3, PROTOCOL_TLSv1 and PROTOCOL_TLSv1_1 (SSLContext(), wrap_socket(ssl_version=...), a requests/urllib3 adapter), the pyOpenSSL methods SSLv2_METHOD, SSLv3_METHOD, TLSv1_METHOD and TLSv1_1_METHOD, a minimum_version or maximum_version set (by assignment or keyword) to TLSVersion.SSLv3, TLSv1 or TLSv1_1, and an options &= ~OP_NO_SSLv2/SSLv3/TLSv1/TLSv1_1 that re-enables an old protocol. These versions have practical attacks (POODLE, BEAST) and no AEAD ciphers. Use PROTOCOL_TLS_CLIENT/PROTOCOL_TLS_SERVER (or TLS_METHOD) with minimum_version = TLSVersion.TLSv1_2 or higher. Not reported: PROTOCOL_TLSv1_2, PROTOCOL_TLS, PROTOCOL_SSLv23 and SSLv23_METHOD (which negotiate the highest version), OP_NO_* used to disable an old protocol, a comparison against a weak constant (a guard that rejects it), import lines, and the names in comments or string literals (hasattr/getattr probes).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-021/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [326],
	"capec": ["CAPEC-217"],
	"attack_technique": ["T1040"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["ssl", "tls", "cryptography", "python"],
}

_code(line) := regex.replace(
	regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`),
	`#.*$`, "",
)

_const_re := `(?:^|[^\w])((?:PROTOCOL_(?:SSLv2|SSLv3|TLSv1|TLSv1_1))|(?:(?:SSLv2|SSLv3|TLSv1|TLSv1_1)_METHOD))\b`

_version_re := `\b(?:minimum|maximum)_version\s*=\s*[\w.]*TLSVersion\.(SSLv3|TLSv1|TLSv1_1)\b`

_reenable_re := `&=\s*~\s*\(?\s*[\w.]*OP_NO_(SSLv2|SSLv3|TLSv1|TLSv1_1)\b`

# The constant in a comparison: a guard rejecting the weak protocol.
_compared(code, c) if regex.match(concat("", [`(?:[=!]=|\bis(?:\s+not)?|\bin)\s*[\w.]*`, c, `\b`]), code)

_compared(code, c) if regex.match(concat("", [c, `\s*(?:[=!]=|\bis\b|\bin\b)`]), code)

_h1(code) := {sprintf("deprecated protocol constant %v", [m[0][1]]) |
	m := regex.find_all_string_submatch_n(_const_re, code, 1)
	count(m) > 0
	not _compared(code, m[0][1])
}

_h2(code) := {sprintf("TLS version bound set to %v", [m[0][1]]) |
	m := regex.find_all_string_submatch_n(_version_re, code, 1)
	count(m) > 0
}

_h3(code) := {sprintf("OP_NO_%v cleared, re-enabling the protocol", [m[0][1]]) |
	m := regex.find_all_string_submatch_n(_reenable_re, code, 1)
	count(m) > 0
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`SSLv[23]|TLSv1`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`SSLv[23]|TLSv1`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:from\s+\S+\s+)?import\s`, line)
	code := _code(line)
	hits := (_h1(code) | _h2(code)) | _h3(code)
	count(hits) > 0
	what := sort(hits)[0]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak SSL/TLS: %v; use PROTOCOL_TLS_CLIENT/TLS_METHOD with minimum_version = TLSVersion.TLSv1_2 or higher", [what]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

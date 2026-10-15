# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_757

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-757",
	"name": "TLS negotiation allows an obsolete protocol version or broken cipher suite (algorithm downgrade)",
	"description": "A TLS configuration lets the peers negotiate down to SSL 2/3, TLS 1.0 or TLS 1.1, or offers a broken cipher suite. Reported: Go tls.Config MinVersion/MaxVersion set to tls.VersionSSL30, VersionTLS10 or VersionTLS11, and an RC4, 3DES or NULL suite (tls.TLS_..._RC4_/3DES_) listed as a CipherSuites element; Java SSLContext.getInstance(\"SSLv3\"|\"TLSv1\"|\"TLSv1.1\"), setEnabledProtocols/setProtocols with an obsolete protocol literal (on the call, on the next two lines, or in a String[] that is passed to it), setEnabledCipherSuites/setCipherSuites with an RC4, DES, NULL, EXPORT or anon suite, System.setProperty of https.protocols or jdk.tls.client/server.protocols naming an obsolete version, and Security.setProperty(\"jdk.tls.disabledAlgorithms\", ...) with a value that no longer disables SSLv3; Python ssl.PROTOCOL_SSLv2/SSLv3/TLSv1/TLSv1_1, pyOpenSSL SSL.SSLv2/SSLv3/TLSv1/TLSv1_1_METHOD, minimum_version set to TLSVersion.SSLv3/TLSv1/TLSv1_1/MINIMUM_SUPPORTED or maximum_version capped at one of them, options &= ~OP_NO_SSLv2/SSLv3/TLSv1/TLSv1_1, and set_ciphers() with an enabled RC4, DES, NULL, EXPORT, LOW or MD5 token or @SECLEVEL=0; and, in any of the three languages, an obsolete protocol string assigned to a name that says it is a protocol or TLS version. Not reported: TLS 1.2/1.3 (TLSv1.2, VersionTLS12, PROTOCOL_TLSv1_2), SSLContext.getInstance(\"TLS\"|\"SSL\"), comparisons and lookup tables of version constants (ctx.protocol == ssl.PROTOCOL_TLSv1, {ssl.PROTOCOL_TLSv1: ...}), protocol names compared or removed while filtering a protocol list (p.equals(\"TLSv1\"), list.remove(\"SSLv3\")), version names in log messages, comments or other string literals, excluded cipher tokens (!RC4, -DES), and test files.",
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
	"tags": ["crypto", "tls", "downgrade", "cwe-757"],
}

# Whole-file gate: a file that names none of these cannot match any shape below.
_gate := `VersionTLS1[01]|VersionSSL30|RC4|3DES|SSLv[23]|TLSv1|OP_NO_|set_ciphers|MINIMUM_SUPPORTED|disabledAlgorithms`

# An obsolete protocol name, written exactly: TLSv1 or TLSv1.0/TLSv1.1, not TLSv1.2.
_old_proto_lit := `"(?:SSLv2Hello|SSLv2|SSLv3|TLSv1|TLSv1\.0|TLSv1\.1)"`

_old_proto_tok := `(?:SSLv[23]|TLSv1(?:\.[01])?)(?:[^.\w]|$)`

_messages := {
	"a broken cipher suite is enabled",
	"an obsolete protocol is enabled",
	"an obsolete protocol version is configured",
	"an obsolete pyOpenSSL method is used",
	"an obsolete ssl protocol constant is used",
	"an OP_NO_ protection flag is cleared",
	"an RC4/3DES/NULL cipher suite is offered",
	"a system property enables an obsolete protocol",
	"jdk.tls.disabledAlgorithms no longer disables SSLv3",
	"MinVersion/MaxVersion is set to SSL 3.0, TLS 1.0 or TLS 1.1",
	"set_ciphers enables a broken cipher",
	"SSLContext.getInstance requests an obsolete protocol",
	"the maximum TLS version is capped at an obsolete one",
	"the minimum TLS version is lowered",
}

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_ext(path) := "go" if endswith(path, ".go")

_ext(path) := "java" if endswith(path, ".java")

_ext(path) := "py" if endswith(path, ".py")

findings contains finding if {
	some path, content in input.file_contents
	lang := _ext(path)
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	whats := sort([w | some w in _messages; _hit(w, lang, lines, i, line, content)])
	count(whats) > 0
	what := whats[0]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("TLS negotiation can be downgraded: %s. Require TLS 1.2 or later with AEAD cipher suites", [what]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── any language: an obsolete protocol string given to a protocol/version name
_hit("an obsolete protocol version is configured", _, _, _, line, _) if {
	regex.match(concat("", [`(?i)\b\w*(?:protocols?|tls_?version|ssl_?version|min_?version)\w*\s*(?::=|=|:)\s*`, _old_proto_lit, `\s*[;,)]?\s*$`]), line)
}

# ── Go ────────────────────────────────────────────────────────────────────
_hit("MinVersion/MaxVersion is set to SSL 3.0, TLS 1.0 or TLS 1.1", "go", _, _, line, _) if {
	regex.match(`\b(?:MinVersion|MaxVersion)\s*(?::|=)\s*(?:uint16\()?\w+\.Version(?:SSL30|TLS10|TLS11)\b`, _strip_strings(line))
}

_hit("an RC4/3DES/NULL cipher suite is offered", "go", _, _, line, content) if {
	contains(content, "CipherSuites")
	regex.match(`^\s*(?:CipherSuites:\s*\[\]uint16\{.*)?\w+\.TLS_\w*(?:RC4|3DES|_NULL_)\w*\s*[,}]?\s*(?:\}?,?)?\s*(?://.*)?$`, line)
}

# ── Java ──────────────────────────────────────────────────────────────────
_hit("SSLContext.getInstance requests an obsolete protocol", "java", _, _, line, _) if {
	regex.match(concat("", [`SSLContext\.getInstance\(\s*`, _old_proto_lit]), line)
}

_hit("an obsolete protocol is enabled", "java", lines, i, line, _) if {
	regex.match(_old_proto_lit, _drop_compared(line))
	_near_call(lines, i, `\.set(?:Enabled)?Protocols\(`)
}

# A protocol name that is compared or removed is being filtered out, not
# enabled: stream.filter(p -> !p.equals("TLSv1")), list.remove("SSLv3").
_drop_compared(line) := regex.replace(line, `\.(?:equals|equalsIgnoreCase|remove|removeAll|contains|startsWith|matches)\(\s*"[^"]*"\s*\)`, "")

# String[] PROTOCOLS = {"SSLv3", ...}; ... setEnabledProtocols(PROTOCOLS)
_hit("an obsolete protocol is enabled", "java", _, _, line, content) if {
	regex.match(_old_proto_lit, _drop_compared(line))
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:new\s+String\s*\[\]\s*)?\{`, line, 1)
	count(m) > 0
	regex.match(concat("", [`\.set(?:Enabled)?Protocols\(\s*`, m[0][1], `\s*\)`]), content)
}

_hit("a broken cipher suite is enabled", "java", lines, i, line, _) if {
	regex.match(`"(?:SSL|TLS)_\w*(?:RC4|DES|NULL|EXPORT|anon)\w*"`, line)
	_near_call(lines, i, `\.set(?:Enabled)?CipherSuites\(`)
}

_hit("a system property enables an obsolete protocol", "java", _, _, line, _) if {
	m := regex.find_all_string_submatch_n(`setProperty\(\s*"(?:https\.protocols|jdk\.tls\.(?:client|server)\.protocols)"\s*,\s*"([^"]*)"`, line, 1)
	count(m) > 0
	regex.match(_old_proto_tok, m[0][1])
}

_hit("jdk.tls.disabledAlgorithms no longer disables SSLv3", "java", _, _, line, _) if {
	m := regex.find_all_string_submatch_n(`Security\.setProperty\(\s*"jdk\.tls\.disabledAlgorithms"\s*,\s*"([^"]*)"`, line, 1)
	count(m) > 0
	not contains(m[0][1], "SSLv3")
}

_near_call(lines, i, call_re) if {
	some j in numbers.range(max([0, i - 2]), i)
	regex.match(call_re, lines[j])
}

# ── Python ────────────────────────────────────────────────────────────────
_hit("an obsolete ssl protocol constant is used", "py", _, _, line, _) if {
	regex.match(`\bPROTOCOL_(?:SSLv2|SSLv3|TLSv1|TLSv1_1)\b`, _drop_py_lookups(_strip_strings(line)))
}

# ctx.protocol == ssl.PROTOCOL_TLSv1, `in (ssl.PROTOCOL_TLSv1_1,)` and a
# {ssl.PROTOCOL_TLSv1: "TLS 1.0"} lookup key inspect a version, not select it.
_drop_py_lookups(code) := regex.replace(code, `(?:[=!]=\s*|\bin\s*[(\[{]\s*)(?:\w+\.)*PROTOCOL_\w+|(?:\w+\.)*PROTOCOL_\w+\s*:`, "")

_hit("an obsolete pyOpenSSL method is used", "py", _, _, line, _) if {
	regex.match(`\bSSL\.(?:SSLv2|SSLv3|TLSv1|TLSv1_1)_METHOD\b`, _strip_strings(line))
}

_hit("the minimum TLS version is lowered", "py", _, _, line, _) if {
	regex.match(`\bminimum_version\s*=\s*(?:\w+\.)?TLSVersion\.(?:SSLv3|TLSv1|TLSv1_1|MINIMUM_SUPPORTED)\b`, _strip_strings(line))
}

_hit("the maximum TLS version is capped at an obsolete one", "py", _, _, line, _) if {
	regex.match(`\bmaximum_version\s*=\s*(?:\w+\.)?TLSVersion\.(?:SSLv3|TLSv1|TLSv1_1)\b`, _strip_strings(line))
}

_hit("an OP_NO_ protection flag is cleared", "py", _, _, line, _) if {
	regex.match(`&=\s*~\s*\(?\s*(?:\w+\.)?OP_NO_(?:SSLv2|SSLv3|TLSv1|TLSv1_1)\b`, _strip_strings(line))
}

_hit("set_ciphers enables a broken cipher", "py", _, _, line, _) if {
	m := regex.find_all_string_submatch_n(`\.set_ciphers\(\s*['"]([^'"]*)['"]`, line, 1)
	count(m) > 0
	some tok in split(m[0][1], ":")
	_weak_cipher_token(trim_space(tok))
}

_weak_cipher_token(tok) if {
	not startswith(tok, "!")
	not startswith(tok, "-")
	regex.match(`^\+?(?:RC4|DES|3DES|NULL|eNULL|aNULL|EXPORT|EXP|LOW|MD5)(?:$|[-+])|-(?:RC4|DES|NULL|MD5)(?:$|-)`, tok)
}

_weak_cipher_token(tok) if contains(tok, "@SECLEVEL=0")

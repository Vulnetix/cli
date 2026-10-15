# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_733

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-733",
	"name": "Compiler Optimization Removal or Modification of Security-critical Code",
	"description": "Security-critical C or C++ code that the optimiser is allowed to delete. Two shapes are reported. A dead-store wipe: memset/std::memset/bzero/ZeroMemory/RtlZeroMemory with a zero fill of a buffer named as a secret (password, passwd, passphrase, pwd, secret, key, private key, seed, pin, token, credential, plaintext; prefixes and camelCase included) whose next statement frees it (free, OPENSSL_free, g_free, kfree, delete) or, for a plain local name, returns or closes the scope, so nothing reads the cleared memory and the clear can be removed (CWE-14). And a pointer-wraparound bounds check in an if condition, p + n < p or p + n <= p (also written p > p + n), on a name declared as a pointer in the same file: pointer overflow is undefined behaviour, so compilers fold the test to false and drop the check; a check on a line without if (an assert, a return expression) is not read. Not reported: explicit_bzero, memset_s, SecureZeroMemory, OPENSSL_cleanse, sodium_memzero and other guaranteed wipes; a clear followed by a use of the buffer (initialisation); a clear of a struct member before return (caller-owned memory); non-zero fills; the same arithmetic test on integers (size_t a + b < a is a well-defined unsigned overflow check), checks written as n > end - p; test code, comments and strings. VNX-CWE1037-AUTO reports the dead-store wipe as well.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-733/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [733],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["compiler-removal", "dead-store", "undefined-behaviour", "cwe-733"],
}

_is_c(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
}

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# ── Dead-store wipe ──────────────────────────────────────────────────────

_wipe_re := `(?:^|[^\w.>])(?:std::)?(memset|bzero|ZeroMemory|RtlZeroMemory)\s*\(\s*&?\s*\(?\s*([A-Za-z_][\w]*(?:(?:->|\.)[A-Za-z_]\w*)*)`

_secret_re := `(?:^|_)(?i:pass(?:word|wd|phrase)?|pwd|secret|priv(?:ate)?_?key|key|seed|pin|token|cred(?:ential)?s?|plaintext)(?:_?(?i:buf(?:fer)?))?$|[a-z0-9](?:Pass(?:word|wd|phrase)?|Pwd|Secret|Key|Seed|Pin|Token|Cred(?:ential)?s?|Plaintext)(?:_?Buf(?:fer)?)?$`

_zero_fill(fn, code) if fn in {"bzero", "ZeroMemory", "RtlZeroMemory"}

_zero_fill("memset", code) if regex.match(`memset\s*\([^,]+,\s*(0|'\\0'|0x0+|\(char\)\s*0)\s*,`, code)

_last_segment(name) := s if {
	parts := regex.split(`->|\.`, name)
	s := parts[count(parts) - 1]
}

_dead_after(lines, i, name) if {
	j := _next_stmt(lines, i)
	esc := regex.replace(name, `([.\[\]>-])`, `\$1`)
	regex.match(concat("", [`(?:^|[^\w.>])(free|OPENSSL_free|g_free|kfree|kvfree|vfree|HeapFree|LocalFree|CRYPTO_free)\s*\([^)]*\b`, esc, `\s*\)|\bdelete\s*(\[\s*\])?\s*`, esc, `\s*;`]), lines[j])
}

_dead_after(lines, i, name) if {
	regex.match(`^[A-Za-z_]\w*$`, name)
	j := _next_stmt(lines, i)
	regex.match(`^\s*(return\b|\}\s*$)`, lines[j])
	not regex.match(concat("", [`\b`, name, `\b`]), lines[j])
	_local_array(lines, i, name)
}

# A stack array or struct declared in the function above the wipe, not a
# pointer parameter whose memory belongs to the caller.
_local_array(lines, i, name) if {
	some k in numbers.range(max([0, i - 60]), i - 1)
	regex.match(concat("", [`^\s+(?:unsigned\s+|const\s+|volatile\s+|struct\s+)*[A-Za-z_][\w:<>]*\s+`, name, `\s*(\[[^\]]*\]\s*)+(=|;)|^\s+(?:struct\s+)?[A-Za-z_][\w:<>]*\s+`, name, `\s*;`]), lines[k])
}

_kind(lines, i, code) := "wipe" if {
	m := regex.find_all_string_submatch_n(_wipe_re, code, 1)
	count(m) > 0
	name := m[0][2]
	regex.match(_secret_re, _last_segment(name))
	_zero_fill(m[0][1], code)
	_dead_after(lines, i, name)
}

# ── Pointer wraparound check ─────────────────────────────────────────────

_wrap_names(code) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*\+\s*[\w\->\.\(\)\*]+\s*<=?\s*([A-Za-z_]\w*)\b`, code, -1)
	m[1] == m[2]
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*>=?\s*([A-Za-z_]\w*)\s*\+\s*[\w\->\.\(\)\*]+`, code, -1)
	m[1] == m[2]
}

_is_pointer(content, name) if regex.match(concat("", [`\*\s*(const\s+)?`, name, `\s*[,;=)\[]`]), content)

_kind(lines, i, code) := "wrap" if {
	regex.match(`\bif\s*\(|\bassert\s*\(|&&|\|\|`, code)
	some name in _wrap_names(code)
	_is_pointer(concat("\n", lines), name)
}

_message := {
	"wipe": "This clear of a secret is a dead store: nothing reads the buffer before it is freed or goes out of scope, so the compiler may delete the memset and leave the secret in memory. Use explicit_bzero, memset_s, SecureZeroMemory or OPENSSL_cleanse",
	"wrap": "Pointer-overflow check: p + n < p is undefined behaviour, so the compiler may assume it is false and remove the check. Compare lengths instead (n > (size_t)(end - p))",
}

_gate(content) if contains(content, "memset")

_gate(content) if contains(content, "bzero")

_gate(content) if contains(content, "ZeroMemory")

_gate(content) if regex.match(`if\s*\(\s*[A-Za-z_]\w*\s*\+[^;\n]*[<>]|[<>]=?\s*[A-Za-z_]\w*\s*\+`, content)

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	not helpers.is_test_path(path)
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	_line_gate(line)
	not helpers.is_comment_line(line)
	code := _code(line)
	kind := _kind(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": _message[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The next code line after the wipe that is not itself another wipe (several
# buffers are commonly cleared in a row before one return).
_next_stmt(lines, i) := j if {
	end := min([count(lines) - 1, i + 6])
	i + 1 <= end
	cands := [k |
		some k in numbers.range(i + 1, end)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
		not regex.match(`^\s*(?:std::)?(memset|bzero|ZeroMemory|RtlZeroMemory|explicit_bzero|OPENSSL_cleanse)\s*\(`, lines[k])
	]
	count(cands) > 0
	j := cands[0]
}

_line_gate(line) if contains(line, "memset")

_line_gate(line) if contains(line, "bzero")

_line_gate(line) if contains(line, "ZeroMemory")

_line_gate(line) if {
	contains(line, "+")
	contains(line, "<")
	contains(line, "if")
}

_line_gate(line) if {
	contains(line, "+")
	contains(line, ">")
	contains(line, "if")
}

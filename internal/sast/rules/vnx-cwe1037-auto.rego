# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1037

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1037",
	"name": "Processor Optimization Removal of Security-critical Code",
	"description": "Key material, passwords or other secrets are wiped with memset/std::memset, bzero, ZeroMemory or RtlZeroMemory immediately before the memory is released, so the wipe is a dead store that an optimizer is allowed to delete, leaving the secret in freed heap or stack memory. Processor-level removal of security code (speculative execution) has no line-level signature; this rule reports the concrete optimizer case, the compiler dead-store elimination of a buffer clear (CWE-14). Reported in C and C++: a zeroing call (fill value 0, '\\0' or 0x00) whose buffer is named as a secret (key, password, passwd, passphrase, pwd, pin, otp, secret, seed, token, cred/credential, plaintext, master; camelCase and prefixes such as szPassword or session_key included) and whose next statements, before any read of the buffer, free it (free, OPENSSL_free, g_free, kfree, HeapFree, LocalFree, delete ...) or, for a local array, struct or std::array declared in the function, return or close its scope. Not reported: explicit_bzero, memset_s, SecureZeroMemory, RtlSecureZeroMemory, OPENSSL_cleanse, sodium_memzero and other guaranteed wipes; a clear followed by a read of the buffer or a compiler barrier that names it (initialisation, asm volatile); a clear of caller-owned memory (a pointer parameter or a struct member that outlives the function); buffers not named as secrets; non-zero fill patterns; test code, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1037/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1037, 14],
	"capec": ["CAPEC-188"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["optimization", "memset", "volatile", "dead-store", "memory-zeroing", "cwe-1037"],
}

_c_file(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx"}
	endswith(path, ext)
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_zero_needles := {"memset", "bzero", "ZeroMemory"}

# The buffer argument of a zeroing call that writes zeros.
_zero_res := [
	`(?:^|[^\w.>])(?:std::|::)?memset\s*\(\s*([^,]+?)\s*,\s*(?:0[xX]0+|0+[uUlL]*|'\\0'|'\\x0+'|\(\s*char\s*\)\s*0)\s*(?:,|$)`,
	`(?:^|[^\w.>])bzero\s*\(\s*([^,]+?)\s*,`,
	`(?:^|[^\w.>])(?:Rtl)?ZeroMemory\s*\(\s*([^,]+?)\s*,`,
]

_buffer(line) := b if {
	some re in _zero_res
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	b := m[0][1]
}

_cast_words := {"void", "char", "unsigned", "signed", "const", "volatile", "uint8_t", "int8_t", "u8", "BYTE", "PVOID", "LPVOID", "data", "c_str", "begin", "get"}

_idents(expr) := [x | some x in regex.find_all_string_submatch_n(`[A-Za-z_]\w*`, expr, -1); not x[0] in _cast_words]

_base(expr) := ids[0][0] if {
	ids := _idents(expr)
	count(ids) > 0
}

_snake(name) := lower(regex.replace(name, `([a-z0-9])([A-Z])`, "${1}_${2}"))

_secret_re := `(^|_)(key|keys|keybuf|keydata|keymat|privkey|prvkey|seckey|secret|secrets|password|passwd|passphrase|pass|pwd|pw|pin|otp|seed|token|tokens|cred|creds|credential|credentials|plaintext|master)(_|$|[0-9])`

_secret(expr) if {
	some x in _idents(expr)
	regex.match(_secret_re, _snake(x[0]))
}

# The line that ends the zeroing call (it may wrap).
_call_end(lines, i) := k if {
	ks := [j | some j in numbers.range(i, min([count(lines) - 1, i + 3])); contains(lines[j], ";")]
	count(ks) > 0
	k := ks[0]
}

_refs(line, name) if regex.match(concat("", [`(^|[^\w.>])`, name, `\b`]), line)

_free_re := `^\s*(?:(?:std::)?free|OPENSSL_free|OPENSSL_clear_free|g_free|kfree|vfree|zfree|xfree|HeapFree|LocalFree|GlobalFree|CoTaskMemFree|VirtualFree|sodium_free|av_free|av_freep|delete\s*\[\s*\]|delete)\b`

# The first statement after the call that reads the buffer, returns or closes
# a scope, within a few statements.
_next_event(lines, ce, base) := t if {
	n := count(lines)
	ce + 1 <= n - 1
	cands := [k |
		some k in numbers.range(ce + 1, min([n - 1, ce + 12]))
		l := lines[k]
		trim_space(l) != ""
		not helpers.is_comment_line(l)
	]
	near := array.slice(cands, 0, 5)
	evs := [k |
		some k in near
		_event(lines[k], base)
	]
	count(evs) > 0
	t := evs[0]
}

_event(line, base) if _refs(line, base)

_event(line, _) if regex.match(`^\s*return\b`, line)

_event(line, _) if startswith(trim_space(line), "}")

# A local object (array, struct, std::array) declared in this function.
_fn_start(lines, i) := max(array.concat([max([0, i - 150])], [j |
	some j in numbers.range(max([0, i - 150]), i)
	l := lines[j]
	regex.match(`^(\{|[A-Za-z_].*\)\s*(const\s*)?\{?\s*$)`, l)
]))

_decl_re(name) := concat("", [
	`^\s*(?:(?:const|volatile|unsigned|signed|struct|union|register|auto)\s+)*[A-Za-z_][\w:]*(?:\s*<[^;()]*>)?\s+(?:[A-Za-z_]\w*\s*(?:\[[^\]]*\])*\s*(?:=[^,;]*)?,\s*)*`,
	name,
	`\s*(?:\[[^\]]*\])*\s*(?:\{[^;]*\}|=[^;]*)?\s*[;,]`,
])

_local(lines, i, name) if {
	fs := _fn_start(lines, i)
	fs <= i - 1
	re := _decl_re(name)
	some j in numbers.range(fs, i - 1)
	l := lines[j]
	contains(l, name)
	not regex.match(`^\s*(return|delete|throw|goto|case|else|static|extern|typedef)\b`, l)
	regex.match(re, l)
}

# After a scope-closing brace that is not the end of the function, the buffer
# must not be read again.
_used_after(lines, t, base) if {
	not startswith(lines[t], "}")
	some k in numbers.range(t + 1, min([count(lines) - 1, t + 15]))
	not helpers.is_comment_line(lines[k])
	_refs(lines[k], base)
}

_dead(lines, t, base) if {
	regex.match(_free_re, lines[t])
	_refs(lines[t], base)
}

_dead(lines, t, base) if {
	not _refs(lines[t], base)
	regex.match(`^\s*return\b`, lines[t])
}

_dead(lines, t, base) if {
	not _refs(lines[t], base)
	startswith(trim_space(lines[t]), "}")
	not _used_after(lines, t, base)
}

_needs_local(lines, t) if not regex.match(_free_re, lines[t])

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	_has_any(content, _zero_needles)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _zero_needles)
	not helpers.is_comment_line(line)
	code := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)
	expr := _buffer(code)
	_secret(expr)
	base := _base(expr)
	ce := _call_end(lines, i)
	t := _next_event(lines, ce, base)
	_dead(lines, t, base)
	_local_ok(lines, i, t, base)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is cleared just before it is freed or goes out of scope: the optimizer may delete this dead store and leave the secret in memory. Use explicit_bzero, memset_s, SecureZeroMemory/RtlSecureZeroMemory, OPENSSL_cleanse or sodium_memzero", [trim_space(expr)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_local_ok(lines, _, t, _) if not _needs_local(lines, t)

_local_ok(lines, i, t, base) if {
	_needs_local(lines, t)
	_local(lines, i, base)
}

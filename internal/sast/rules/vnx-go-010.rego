package vulnetix.rules.vnx_go_010

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-010",
	"name": "Go weak cipher usage",
	"description": "Go code constructs a broken or deprecated cipher: des.NewCipher (DES, 56-bit key), des.NewTripleDESCipher (3DES, deprecated by NIST, Sweet32), rc4.NewCipher (RC4, keystream biases), or the 64-bit-block ciphers golang.org/x/crypto/blowfish, cast5, tea and xtea (deprecated by the Go project). A call or a constructor passed as a value (a table of ciphers) is reported, with an aliased import resolved; so is an RC4 or 3DES TLS cipher suite (tls.TLS_*_RC4_128_*, tls.TLS_*_3DES_EDE_CBC_*) placed in a tls.Config CipherSuites list, and a legacy SSH cipher (\"3des-cbc\", \"arcfour\", \"arcfour128\", \"arcfour256\") placed in an x/crypto/ssh Ciphers list, which x/crypto/ssh leaves disabled unless a config names it; for both, the list may be inline, a []uint16{/[]string{ literal opened above, or a variable the CipherSuites/Ciphers field takes. Not reported: the import alone, constants such as des.BlockSize and des.KeySizeError, blowfish.NewSaltedCipher (the bcrypt key schedule), a TLS suite or SSH cipher named in a deny-list or comparison, comments and string literals, and test files (a cipher in a test protects no data). Use AES-GCM or ChaCha20-Poly1305.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-010/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "weak-cipher", "des", "rc4"],
}

# import path -> default package name, constructors, label
_algos := {
	"crypto/des": {"pkg": "des", "funcs": `NewCipher|NewTripleDESCipher`, "label": "DES/3DES"},
	"crypto/rc4": {"pkg": "rc4", "funcs": `NewCipher`, "label": "RC4"},
	"golang.org/x/crypto/blowfish": {"pkg": "blowfish", "funcs": `NewCipher`, "label": "Blowfish"},
	"golang.org/x/crypto/cast5": {"pkg": "cast5", "funcs": `NewCipher`, "label": "CAST5"},
	"golang.org/x/crypto/tea": {"pkg": "tea", "funcs": `NewCipher|NewCipherWithRounds`, "label": "TEA"},
	"golang.org/x/crypto/xtea": {"pkg": "xtea", "funcs": `NewCipher`, "label": "XTEA"},
}

_gate(content) if contains(content, "\"crypto/des\"")

_gate(content) if contains(content, "\"crypto/rc4\"")

_gate(content) if contains(content, "\"golang.org/x/crypto/")

_gate(content) if contains(content, "_RC4_128_")

_gate(content) if contains(content, "_3DES_EDE_CBC_")

_import_re(ip) := concat("", [`(?m)^\s*(?:import\s+)?(?:([A-Za-z_]\w*)\s+)?"`, replace(ip, ".", `\.`), `"\s*(?://.*)?$`])

# The package's local name in this file (an alias wins; a blank import has none).
_local(content, ip, def) := name if {
	m := regex.find_all_string_submatch_n(_import_re(ip), content, 1)
	count(m) > 0
	m[0][1] == ""
	name := def
}

_local(content, ip, _) := name if {
	m := regex.find_all_string_submatch_n(_import_re(ip), content, 1)
	count(m) > 0
	not m[0][1] in {"", "_"}
	name := m[0][1]
}

# The code on a line: string literals and a trailing // comment removed.
_code(line) := c if {
	s := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`)
	c := regex.replace(s, `//.*$`, "")
}

# Inside a /* ... */ block whose continuation lines carry no leading '*'.
_in_block_comment(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 60]), i - 1)
	contains(lines[j], "/*")
	not contains(substring(lines[j], indexof(lines[j], "/*") + 2, -1), "*/")
	not _closed_between(lines, j, i)
}

_closed_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	contains(lines[k], "*/")
}

# A weak suite inside a CipherSuites list: on the same line, or in the
# []uint16{...} literal opened above and not yet closed.
_in_cipher_suites(_, _, code, _) if regex.match(`\bCipherSuites\b`, code)

_in_cipher_suites(lines, i, _, _) if {
	i > 0
	some j in numbers.range(max([0, i - 30]), i - 1)
	regex.match(`\bCipherSuites\s*(?::|=)\s*\[\]uint16\s*\{\s*$`, lines[j])
	not _brace_closed_between(lines, j, i)
}

# ...or in a []uint16{...} list held in a variable that a CipherSuites field
# of this file takes (CipherSuites: legacySuites). A deny-list that is only
# compared against is not configuration.
_in_cipher_suites(lines, i, _, svars) if {
	i > 0
	count(svars) > 0
	some j in numbers.range(max([0, i - 30]), i - 1)
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?(\w+)\s*(?::?=)\s*\[\]uint16\s*\{\s*$`, lines[j], 1)
	count(m) > 0
	m[0][1] in svars
	not _brace_closed_between(lines, j, i)
}

# Variables a CipherSuites field is set from.
_suite_vars(content) := {m[1] |
	contains(content, "CipherSuites")
	some m in regex.find_all_string_submatch_n(`\bCipherSuites\s*(?::|=)\s*(?:append\(\s*)?([A-Za-z_]\w*)\b`, content, -1)
}

_brace_closed_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	contains(lines[k], "}")
}

_weak_suite_re := `\btls\.(TLS_\w*?(?:RC4_128|3DES_EDE_CBC)\w*)`

_hit(_, _, code, uses, _) := label if {
	some u in uses
	regex.match(concat("", [`(?:^|[^\w.])`, u.name, `\.(?:`, u.funcs, `)\b`]), code)
	label := u.label
}

_hit(lines, i, code, _, svars) := label if {
	m := regex.find_all_string_submatch_n(_weak_suite_re, code, 1)
	count(m) > 0
	_in_cipher_suites(lines, i, code, svars)
	label := concat("", ["TLS suite ", m[0][1]])
}

# x/crypto/ssh disables its legacy ciphers unless a config names them: a
# "3des-cbc" or "arcfour*" entry in a Ciphers list (same line, an open
# []string{ literal, or a variable a Ciphers field takes) turns them back on.
_ssh_weak_re := `"(3des-cbc|arcfour(?:128|256)?)"`

_in_ssh_ciphers(_, _, code, _) if regex.match(`\bCiphers\s*(?::|=)`, code)

_in_ssh_ciphers(lines, i, _, _) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(`\bCiphers\s*(?::|=)\s*\[\]string\s*\{\s*$`, lines[j])
	not _brace_closed_between(lines, j, i)
}

_in_ssh_ciphers(lines, i, _, cvars) if {
	count(cvars) > 0
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?(\w+)\s*(?::?=)\s*\[\]string\s*\{`, lines[i], 1)
	count(m) > 0
	m[0][1] in cvars
}

_in_ssh_ciphers(lines, i, _, cvars) if {
	count(cvars) > 0
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?(\w+)\s*(?::?=)\s*\[\]string\s*\{\s*$`, lines[j], 1)
	count(m) > 0
	m[0][1] in cvars
	not _brace_closed_between(lines, j, i)
}

_ssh_cipher_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\bCiphers\s*(?::|=)\s*(?:append\(\s*)?([A-Za-z_]\w*)\b`, content, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "\"golang.org/x/crypto/ssh\"")
	regex.match(`"(?:3des-cbc|arcfour)`, content)
	not helpers.is_test_path(path)
	cvars := _ssh_cipher_vars(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "\"")
	m := regex.find_all_string_submatch_n(_ssh_weak_re, line, 1)
	count(m) > 0
	not helpers.is_comment_line(line)
	not _in_block_comment(lines, i)
	_in_ssh_ciphers(lines, i, _code(line), cvars)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak cipher: SSH cipher %s (3DES/RC4) is enabled; x/crypto/ssh leaves it off by default. Use chacha20-poly1305@openssh.com or aes*-gcm@openssh.com", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_gate(content)
	not helpers.is_test_path(path)
	uses := {{"name": n, "funcs": a.funcs, "label": a.label} |
		some ip, a in _algos
		contains(content, concat("", ["\"", ip, "\""]))
		n := _local(content, ip, a.pkg)
	}
	svars := _suite_vars(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:New\w*Cipher\w*|TLS_\w+)\b`, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some label in {l | l := _hit(lines, i, code, uses, svars)}
	not _in_block_comment(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak cipher: %s is broken or deprecated; use AES-GCM (crypto/aes with cipher.NewGCM) or ChaCha20-Poly1305", [label]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

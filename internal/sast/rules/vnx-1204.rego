# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1204

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1204",
	"name": "Generation of Weak Initialization Vector (IV)",
	"description": "Reports Java code that builds a cipher IV or nonce (IvParameterSpec, GCMParameterSpec, ChaCha20ParameterSpec) from bytes that are not freshly random: a zero-filled new byte[N] passed straight to the spec; a byte[] allocated with new byte[N] and handed to the spec within the next 40 lines without anything filling it (no nextBytes, read, readFully, ByteBuffer.get, System.arraycopy, element assignment or other call that takes the array); a byte[] initialised from a literal ({...}, new byte[]{...}, \"...\".getBytes()) that the file uses as an IV; a string literal's bytes passed to the spec; and an IV filled by java.util.Random or ThreadLocalRandom.nextBytes. A zero, constant or predictable IV repeats across messages, which leaks plaintext equality under CBC and breaks confidentiality and authentication under CTR and GCM. Not reported: IVs filled by SecureRandom, IVs read from the message being decrypted, cipher.getIV(), byte arrays never used as an IV, strings and comments. Overlaps VNX-JAVA-020 (static IV) and VNX-329 (predictable IV); VNX-CRYPTO-010 (hard-coded IV, nonce or salt) leaves the Java IV lines this rule reports to it.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1204/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1204],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["generation-of-weak-iv", "cwe-1204"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# String literal contents removed; the quotes stay so "...".getBytes() is
# still recognisable.
_code(line) := regex.replace(line, `"(?:\\.|[^"\\])*"`, `""`)

_spec := `new\s+(?:javax\.crypto\.spec\.)?(?:IvParameterSpec|GCMParameterSpec|ChaCha20ParameterSpec)\s*\(`

# The array is the spec's IV argument: first, or after the GCM tag length.
_used_as_iv_re(v) := concat("", [`(?:IvParameterSpec|GCMParameterSpec|ChaCha20ParameterSpec)\s*\(\s*(?:[^,()]+,\s*)?`, v, `\s*[,)]`])

_gate(content) if {
	contains(content, "ParameterSpec")
	contains(content, "javax.crypto")
}

# ── zero-filled or literal bytes passed straight to the spec ────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ParameterSpec")
	not helpers.is_comment_line(line)
	code := _code(_spec_text(lines, i, line))
	regex.match(concat("", [_spec, `.*(?:new\s+byte\s*\[[^\]]+\]|new\s+byte\s*\[\s*\]\s*\{|""\s*\.getBytes\()`]), code)
	finding := _finding(path, i, line, "The IV is a zero-filled array or a constant: every message encrypted under this key uses the same IV. Generate a fresh IV with SecureRandom.nextBytes for each encryption and send it with the ciphertext")
}

# ── a byte[] initialised from a literal and used as the IV ──────────────

_decl_re := `\bbyte\s*(?:\[\s*\]\s+([A-Za-z_]\w*)|\s([A-Za-z_]\w*)\s*\[\s*\])\s*=\s*(.*)$`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_gate(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "byte")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_decl_re, _code(line), 1)
	count(m) > 0
	v := concat("", [m[0][1], m[0][2]])
	regex.match(`^(?:\{|new\s+byte\s*\[\s*\]\s*\{|""\s*\.getBytes\()`, trim_space(m[0][3]))
	regex.match(_used_as_iv_re(v), content)
	finding := _finding(path, i, line, sprintf("%s is a constant byte array and is used as a cipher IV: the IV never changes. Generate a fresh IV with SecureRandom.nextBytes for each encryption", [v]))
}

# ── a byte[] allocated and used as the IV without being filled ──────────

_alloc_re := `\bbyte\s*(?:\[\s*\]\s+([A-Za-z_]\w*)|\s([A-Za-z_]\w*)\s*\[\s*\])\s*=\s*new\s+byte\s*\[[^\]]+\]\s*;`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_gate(content)
	lines := split(content, "\n")
	n := count(lines) - 1
	some i, line in lines
	contains(line, "new byte")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_alloc_re, line, 1)
	count(m) > 0
	v := concat("", [m[0][1], m[0][2]])
	use_re := _used_as_iv_re(v)
	uses := [j |
		some j in numbers.range(i + 1, min([n, i + 40]))
		contains(lines[j], "ParameterSpec")
		regex.match(use_re, concat(" ", [lines[j], _next(lines, j, n)]))
	]
	count(uses) > 0
	not _filled(lines, i, uses[0], v)
	finding := _finding(path, i, line, sprintf("%s is allocated and passed to the cipher as its IV without being filled, so the IV is all zeros on every call. Fill it with SecureRandom.nextBytes(%s) before use", [v, v]))
}

_next(lines, j, n) := lines[j + 1] if j + 1 <= n

else := ""

# Anything that writes the array between allocation and use: a fill call, a
# read, an element store, reassignment, or any call taking it as an argument
# other than the spec itself.
_filled(lines, i, k, v) if {
	some j in numbers.range(i + 1, k)
	l := lines[j]
	not helpers.is_comment_line(l)
	not regex.match(`\bArrays\.fill\s*\(`, l)
	regex.match(concat("", [`(?:\w\s*\(\s*(?:[^;]*,\s*)?`, v, `\s*[,)]|\b`, v, `\s*\[[^\]]*\]\s*=[^=]|\b`, v, `\s*=[^=])`]), l)
	not regex.match(concat("", [`ParameterSpec\s*\(\s*(?:[^,()]+,\s*)?`, v, `\s*[,)]`]), l)
}

# ── an IV filled by a non-cryptographic generator ───────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_gate(content)
	contains(content, "nextBytes")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "nextBytes")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(new\s+(?:java\.util\.)?Random\s*\([^;]*?\)|ThreadLocalRandom\.current\(\)|\b[A-Za-z_]\w*)\s*\.nextBytes\(\s*([A-Za-z_]\w*)\s*\)`, line, 1)
	count(m) > 0
	_weak_generator(content, m[0][1])
	regex.match(_used_as_iv_re(m[0][2]), content)
	finding := _finding(path, i, line, sprintf("The IV %s is filled by java.util.Random, whose output is predictable from a few observed values. Use SecureRandom.nextBytes", [m[0][2]]))
}

_weak_generator(_, recv) if startswith(recv, "new")

_weak_generator(_, recv) if startswith(recv, "ThreadLocalRandom")

_weak_generator(content, recv) if {
	regex.match(`^[A-Za-z_]\w*$`, recv)
	regex.match(concat("", [`\b(?:java\.util\.)?Random\s+`, recv, `\s*=|\b`, recv, `\s*=\s*new\s+(?:java\.util\.)?Random\s*\(`]), content)
}

# The spec call with the following lines appended while its parentheses are
# still open (an argument list broken over lines).
_spec_text(lines, i, line) := t if {
	regex.match(`ParameterSpec\s*\(`, line)
	_open(line) > 0
	n := count(lines) - 1
	i + 1 <= n
	t2 := concat(" ", [line, trim_space(lines[i + 1])])
	t := _more(lines, i, n, t2)
} else := line

_more(lines, i, n, t) := concat(" ", [t, trim_space(lines[i + 2])]) if {
	_open(t) > 0
	i + 2 <= n
} else := t

_open(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

# ── a String constant whose bytes are the IV ────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	_gate(content)
	contains(content, "getBytes")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "String")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bString\s+([A-Za-z_]\w*)\s*=\s*"[^"]*"\s*;`, line, 1)
	count(m) > 0
	v := m[0][1]
	regex.match(concat("", [`(?:IvParameterSpec|GCMParameterSpec|ChaCha20ParameterSpec)\s*\(\s*(?:[^,()]+,\s*)?`, v, `\s*\.\s*getBytes\s*\(`]), content)
	finding := _finding(path, i, line, sprintf("The string constant %s is used, through getBytes(), as a cipher IV: the IV never changes. Generate a fresh IV with SecureRandom.nextBytes for each encryption", [v]))
}

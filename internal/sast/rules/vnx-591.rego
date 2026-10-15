# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_591

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-591",
	"name": "Password read into a char[] copied into an immutable String",
	"description": "Java cannot lock memory against paging or dumps; the one control it offers for a password is to keep it in a char[] and overwrite the array once used. This rule reports the line that throws that control away by copying a password that an API returned as char[] into an immutable String, which cannot be wiped and stays on the heap (and in swap and heap dumps) until garbage collection: new String(...), String.valueOf(...) or String.copyValueOf(...) applied to Console.readPassword(), JPasswordField/PasswordCallback/KeyStore.PasswordProtection getPassword(), or to a char[] variable declared (char[] or var) or reassigned from one a few lines above, and the deprecated JPasswordField.getText(). Not reported: a char[] that is used and wiped without becoming a String, getPassword() in a file that uses none of JPasswordField, PasswordCallback, KeyStore.PasswordProtection or readPassword (an application class whose getter returns a String), new String over other byte or char arrays, comments and string literals. Native memory locking (mlock/VirtualLock) in C/C++ is not analysed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-591/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [591],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["java", "password", "memory", "sensitive-data", "cwe-591"],
}

# String literals are blanked so a message that quotes the pattern is not code.
_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_to_string := `(?:new\s+String|String\s*\.\s*(?:valueOf|copyValueOf))\s*\(`

# A password API that returns char[], called inside the String conversion.
# Console.readPassword may be split from its receiver over a line break, so the
# conversion line plus the next one is matched.
_inline_re := concat("", [_to_string, `[^;]*?(?:\.readPassword\s*\(|\.getPassword\s*\(\s*\))`])

# char[] NAME = <...>.readPassword(...) / .getPassword()
_char_src_re := `(?:char\s*\[\s*\]\s*|\bvar\s+|^\s*(?:this\s*\.\s*)?)([A-Za-z_]\w*)\s*=\s*[^;]*(?:\.readPassword\s*\(|\.getPassword\s*\(\s*\))`

_msg := "A password returned as char[] is copied into an immutable String, which cannot be wiped and stays in memory (and swap or heap dumps) until garbage collection. Keep it in the char[] and overwrite it with Arrays.fill once used"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`readPassword|JPasswordField|PasswordCallback|PasswordProtection`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`String`, line)
	not helpers.is_comment_line(line)
	_converts(lines, i, content)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_window(lines, i) := concat(" ", [_code(lines[i]), _code(lines[i + 1])]) if {
	i + 1 < count(lines)
} else := _code(lines[i])

# new String(console.readPassword(...)) on the line (or continued on the next).
_converts(lines, i, _) if {
	regex.match(_to_string, _code(lines[i]))
	regex.match(_inline_re, _window(lines, i))
}

# char[] pw = console.readPassword(); ... new String(pw)
_converts(lines, i, _) if {
	c := _code(lines[i])
	regex.match(_to_string, c)
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := _code(lines[j])
	regex.match(`readPassword|getPassword`, prev)
	not helpers.is_comment_line(lines[j])
	m := regex.find_all_string_submatch_n(_char_src_re, prev, 1)
	count(m) > 0
	v := m[0][1]
	regex.match(concat("", [_to_string, `\s*`, v, `\s*\)`]), c)
}

# JPasswordField.getText(): the deprecated accessor that returns a String.
_converts(lines, i, content) if {
	contains(content, "JPasswordField")
	c := _code(lines[i])
	contains(c, ".getText(")
	some v in _password_fields(content)
	regex.match(concat("", [`\b`, v, `\s*\.\s*getText\s*\(\s*\)`]), c)
}

_password_fields(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`JPasswordField\s+([A-Za-z_]\w*)`, content, -1)
}

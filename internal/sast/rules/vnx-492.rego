# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_492

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-492",
	"name": "Use of Inner Class Containing Sensitive Data",
	"description": "A Java inner class (a non-static member class, or an anonymous class created with new X() { ... }) reads a private field of its outer class whose name says it holds a password, passphrase, secret, API key, token, credential, private, master, signing, encryption or HMAC key, or PIN. Inner classes compile to separate top-level classes, so the compiler (before Java 11 nestmates) widens access to the outer class's private field through package-visible accessors any class in the package can call, and the inner instance keeps the outer instance, and the secret, reachable. Reported at the inner class's declaration. Not reported: static nested classes, inner classes that do not use a sensitive field, lambdas, sensitive fields that are not private, test code and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-492/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [492],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["inner-class", "sensitive-data", "cwe-492"],
}

_sensitive_re := `(?i)password|passwd|passphrase|secret|api_?key|(?:private|master|signing|encryption|hmac|aes|crypto)_?key|token|credential|\bpin\b|pincode`

_private_field_re := `^\s*private\s+(?:(?:static|final|transient|volatile)\s+)*[A-Za-z_][\w.]*(?:<[^;=()]*>)?(?:\s*\[\])*\s+([A-Za-z_]\w*)\s*(?:\[\])?\s*(?:=[^=][^;]*)?;`

# A non-static member class, or an anonymous class body.
_inner_re := `^\s*(?:(?:public|protected|private|final|abstract)\s+)*class\s+\w+[^;]*\{?\s*$|\bnew\s+[A-Z][\w.]*(?:<[^>]*>)?\s*\([^;]*\)\s*\{\s*$`

_indent(line) := count(line) - count(trim_left(line, " \t"))

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# The end of the block opened at line k: the next line at k's indent (or
# shallower) that starts with a closing brace, bounded to 150 lines.
_block_end(lines, k) := e if {
	ik := _indent(lines[k])
	hi := min([count(lines) - 1, k + 150])
	ends := [j |
		some j in numbers.range(k + 1, hi)
		_indent(lines[j]) <= ik
		startswith(trim_space(lines[j]), "}")
	]
	e := min(array.concat([hi], ends))
}

_uses(lines, k, name) if {
	re := concat("", [`\b`, name, `\b`])
	some j in numbers.range(k + 1, _block_end(lines, k))
	not helpers.is_comment_line(lines[j])
	regex.match(re, _code(lines[j]))
	not _redeclares(lines, k, name)
}

# The inner class declares its own field or local of that name.
_redeclares(lines, k, name) if {
	re := concat("", [`^\s*(?:(?:private|protected|public|static|final)\s+)*[A-Za-z_][\w.<>\[\]]*\s+`, name, `\s*[=;]`])
	some j in numbers.range(k + 1, _block_end(lines, k))
	regex.match(re, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`(?mi)^\s*private\s+[^;(]*(?:password|passwd|passphrase|secret|api_?key|(?:private|master|signing|encryption|hmac|aes|crypto)_?key|token|credential|pin)\w*\s*[=;\[]`, content)
	lines := split(content, "\n")
	sensitive := {name |
		some l in lines
		startswith(trim_space(l), "private")
		m := regex.find_all_string_submatch_n(_private_field_re, l, 1)
		count(m) > 0
		name := m[0][1]
		regex.match(_sensitive_re, name)
	}
	count(sensitive) > 0
	some k, line in lines
	_indent(line) > 0
	not helpers.is_comment_line(line)
	regex.match(_inner_re, _code(line))
	not regex.match(`\bstatic\b`, line)
	some name in sensitive
	_uses(lines, k, name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Inner class uses the outer class's private sensitive field '%s'; inner classes compile to separate classes that reach private data through package-visible accessors. Use a static nested class that receives only what it needs", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": line,
	}
}

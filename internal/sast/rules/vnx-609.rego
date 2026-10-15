# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_609

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-609",
	"name": "Double-Checked Locking",
	"description": "Reports Java double-checked lazy initialisation on a field that is not volatile: a synchronized (...) block immediately preceded by `if (x == null)`, `if (null == x)` or `if (!flag)` and whose first statement repeats the same check, where x is a field of the same file (declared with private/protected/public/static, annotations such as @Nullable before the modifiers included) without the volatile modifier. Under the Java memory model another thread can see the reference before the constructor's writes, or the flag before the data it guards. Not reported: a volatile field, the local-variable idiom (Helper h = helper; if (h == null) ...) over a volatile field, a single check inside a synchronized method or block, AtomicReference checks, the holder-class idiom, fields declared in another file, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-609/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [609],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["double-checked-locking", "cwe-609"],
}

_checks := [
	`^\s*if\s*\(\s*(?:this\.)?([A-Za-z_]\w*)\s*==\s*null\s*\)`,
	`^\s*if\s*\(\s*null\s*==\s*(?:this\.)?([A-Za-z_]\w*)\s*\)`,
	`^\s*if\s*\(\s*!\s*(?:this\.)?([A-Za-z_]\w*)\s*\)`,
]

_checked(line) := n if {
	some re in _checks
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	n := m[0][1]
}

_skippable(l) if trim_space(l) == ""

_skippable(l) if trim_space(l) == "{"

_skippable(l) if helpers.is_comment_line(l)

_prev_code(lines, i) := k if {
	ks := [j | some j in numbers.range(max([0, i - 3]), i - 1); not _skippable(lines[j])]
	count(ks) > 0
	k := max(ks)
}

_next_code(lines, i) := k if {
	ks := [j | some j in numbers.range(i + 1, min([count(lines) - 1, i + 4])); not _skippable(lines[j])]
	count(ks) > 0
	k := min(ks)
}

_field_decl(lines, n) := [l |
	some l in lines
	contains(l, n)
	regex.match(concat("", [`^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*(?:(?:private|protected|public|static|final|transient|volatile)\s+)+[A-Za-z_][\w.]*(?:\s*<[^;=]*>)?(?:\[\])*\s+`, n, `\s*(?:=|;)`]), l)
]

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "synchronized")
	regex.match(`(?m)^\s*if\s*\(.*(?:==\s*null|null\s*==|!\s*\w+\s*\))`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "synchronized")
	regex.match(`^\s*synchronized\s*\(`, line)
	n := _checked(lines[_prev_code(lines, i)])
	_checked(lines[_next_code(lines, i)]) == n
	decls := _field_decl(lines, n)
	count(decls) > 0
	not _any_volatile(decls)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Double-checked locking on non-volatile field '%s': another thread can observe it before initialisation completes. Declare it volatile or use a holder class", [n]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_any_volatile(decls) if {
	some d in decls
	regex.match(`\bvolatile\b`, d)
}

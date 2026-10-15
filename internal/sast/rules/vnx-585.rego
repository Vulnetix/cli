# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_585

import rego.v1

metadata := {
	"id": "VNX-585",
	"name": "Empty synchronized block",
	"description": "A synchronized (lock) statement in Java or Kotlin whose block holds no code: {} on the same line, or an opening brace (same line or the next) followed only by blank and comment lines before the closing brace. An empty synchronized block protects nothing; it is usually a misplaced critical section or a fragile attempt to wait for another thread. Not reported: synchronized blocks with any statement in them, synchronized methods, comments and string literals that mention synchronized.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-585/",
	"languages": ["java", "kotlin"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [585],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["empty-sync", "cwe-585"],
}

_lang(path) if endswith(path, ".java")

_lang(path) if endswith(path, ".kt")

# The statement, its lock expression (one level of nested parentheses), then
# what follows on the line.
_sync_re := `^\s*synchronized\s*\((?:[^()]|\([^()]*\))*\)\s*(.*)$`

_blank(line) if trim_space(line) == ""

_blank(line) if startswith(trim_space(line), "//")

_blank(line) if startswith(trim_space(line), "/*")

_blank(line) if startswith(trim_space(line), "*")

_strip(s) := trim_space(regex.replace(s, `//.*$|/\*.*?\*/`, ""))

# `{}` or `{ }` on the statement's own line.
_empty(_, _, rest) if regex.match(`^\{\s*\}$`, rest)

# `{` on the line, then only blank and comment lines before `}`.
_empty(lines, i, rest) if {
	rest == "{"
	_closes_next(lines, i + 1)
}

# Allman: `{` on the next line.
_empty(lines, i, "") if {
	i + 1 < count(lines)
	_strip(lines[i + 1]) == "{"
	_closes_next(lines, i + 2)
}

_closes_next(lines, s) if {
	hi := min([count(lines) - 1, s + 10])
	s <= hi
	code := [k | some k in numbers.range(s, hi); not _blank(lines[k])]
	count(code) > 0
	regex.match(`^\}`, _strip(lines[min(code)]))
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "synchronized")
	regex.match(`(?m)^\s*synchronized\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "synchronized")
	m := regex.find_all_string_submatch_n(_sync_re, line, 1)
	count(m) > 0
	_empty(lines, i, _strip(m[0][1]))
	finding := {
		"rule_id": metadata.id,
		"message": "Empty synchronized block: it guards no code. Move the statements that need the lock inside it, or use a proper wait/notify, CountDownLatch or other synchronizer",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_697

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-697",
	"name": "Incorrect comparison: compareTo() against 1/-1, equals(null), or equality with NaN",
	"description": "A Java comparison that cannot mean what it says, so a limit, ordering or validity check silently takes the wrong branch. Reported: the result of compareTo(), compareToIgnoreCase() or a compare() call (Comparator.compare, Integer/Long/Double.compare) tested with == or != against 1 or -1, in either operand order (the contract guarantees only the sign; BigDecimal, String and most comparators return other magnitudes, so amount.compareTo(limit) == 1 is false for many amounts over the limit); x.equals(null), which is always false for a correct equals() and throws NullPointerException when x is null, so it never detects a null; and == or != against Double.NaN or Float.NaN, which is always false (or always true). Not reported: sign tests (> 0, < 0, == 0, >= 1), comparisons with other constants, Double.isNaN/Float.isNaN, x == null and Objects.equals(x, null), test files (where equals(null) checks the equals contract), comments and string literals. Timing-unsafe secret comparison is VNX-385/VNX-CRYPTO-008, String == is VNX-597, boxed == is VNX-595.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-697/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [697],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incorrect-comparison", "cwe-697"],
}

_gate := `compare|equals\s*\(\s*null|\.NaN\b`

_args := `\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_checks := [
	[concat("", [`\bcompare(?:To|ToIgnoreCase)?\s*`, _args, `\s*[!=]=\s*-?\s*1(?:[^\w.]|$)`]), "compareTo()/compare() promises only the sign of its result; test it with > 0 or < 0, not against 1 or -1"],
	[`(?:^|[^\w.])-?\s*1\s*[!=]=\s*[\w.()]*\bcompare(?:To|ToIgnoreCase)?\s*\(`, "compareTo()/compare() promises only the sign of its result; test it with > 0 or < 0, not against 1 or -1"],
	[`\.\s*equals\s*\(\s*null\s*\)`, "x.equals(null) is always false and throws when x is null; test x == null instead"],
	[`[!=]=\s*(?:Double|Float)\s*\.\s*NaN\b|\b(?:Double|Float)\s*\.\s*NaN\s*[!=]=`, "NaN is unequal to everything including itself, so this equality test never holds; use Double.isNaN()/Float.isNaN()"],
]

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some c in _checks
	regex.match(c[0], code)
	finding := {
		"rule_id": metadata.id,
		"message": c[1],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

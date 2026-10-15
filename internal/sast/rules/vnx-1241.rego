# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1241

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1241",
	"name": "Use of Predictable Algorithm in Random Number Generator",
	"description": "A java.util.Random, whose linear congruential algorithm is fully determined by its 48-bit seed, is given an explicit seed in production Java code, so every value it produces can be reproduced by anyone who knows or guesses the seed (a constant, the clock, a counter or a value derived from user data). Reported: new Random(<seed>) and new java.util.Random(<seed>) with any argument (a literal, a constant, System.currentTimeMillis()/nanoTime(), an expression), and <name>.setSeed(...) on a variable or field the same file declares as Random or assigns new Random(...). Not reported: new Random() with no seed (whether its use is security-sensitive is judged by VNX-JAVA-016), SecureRandom and its setSeed (which adds entropy rather than replacing it; seeding SecureRandom is VNX-335), other classes whose name merely contains Random, a method that is itself named setSeed, test code, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1241/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1241],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["predictable-rng", "java", "cwe-1241"],
}

_msg := "java.util.Random is seeded explicitly: its LCG output is fully determined by the seed, so the values can be reproduced. Use java.security.SecureRandom (unseeded) for anything an attacker must not predict"

# String literals blanked so a sentence that mentions new Random(42) is not code.
_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

_seeded_ctor_re := `\bnew\s+(?:java\.util\.)?Random\s*\(\s*[^)\s]`

# Names this file declares or assigns as a java.util.Random.
_random_names(lines) := {n |
	some l in lines
	contains(l, "Random")
	not contains(l, "SecureRandom")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`(?:\b(?:java\.util\.)?Random\s+([A-Za-z_]\w*)\s*[=;,)]|\b([A-Za-z_]\w*)\s*=\s*new\s+(?:java\.util\.)?Random\s*\()`, _code(l), -1)
	some k in [1, 2]
	n := m[k]
	n != ""
}

_report(_, _, line, _) if regex.match(_seeded_ctor_re, _code(line))

# new Random(
#         seed): the seed is on the next code line.
_report(lines, i, line, _) if {
	regex.match(`\bnew\s+(?:java\.util\.)?Random\s*\(\s*$`, _code(line))
	j := helpers.next_code_index(lines, i, 2)
	not regex.match(`^\s*\)`, lines[j])
}

_report(_, _, line, names) if {
	contains(line, "setSeed")
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.]|\bthis\.)([A-Za-z_]\w*)\s*\.\s*setSeed\s*\(`, _code(line), 1)
	count(m) > 0
	m[0][1] in names
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "Random")
	regex.match(`\bnew\s+(?:java\.util\.)?Random\s*\(\s*[^)\s]|\.setSeed\s*\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	names := _random_names(lines)
	some i, line in lines
	regex.match(`Random|setSeed`, line)
	not helpers.is_comment_line(line)
	_report(lines, i, line, names)
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

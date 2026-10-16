# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_682

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-682",
	"name": "Incorrect Calculation",
	"description": "An arithmetic expression that is wrong whatever the input. Reported in C, C++ and Java: an integer division or remainder by a literal zero (a / 0, a % 0, a /= 0, a %= 0, including 0L/0U suffixes), which is undefined behaviour in C and an ArithmeticException in Java. Reported in Java: Math.abs() of hashCode(), Objects.hash(), Arrays.hashCode(), or Random.nextInt()/nextLong() called without a bound (also on new Random() or ThreadLocalRandom.current()), which stays negative for Integer.MIN_VALUE/Long.MIN_VALUE, so the index or shard computed from it can be negative. Not reported: floating-point division by 0.0, hexadecimal or non-zero divisors, division by a variable (VNX-369 covers unchecked external divisors), Math.floorMod, a masked hash (h & 0x7fffffff), Math.abs of a bounded nextInt(n), test code (where dividing by zero is how an exception is provoked), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-682/",
	"languages": ["c", "cpp", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [682],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["incorrect-calculation", "cwe-682"],
}

_is_lang(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java"}
	endswith(path, ext)
}

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), `//.*$|/\*.*?\*/`, "")

_div_zero := `(?:[\w\)\]]\s*[/%]|[/%]=)\s*0+[lLuU]*(?:[^\w.]|$)`

_abs_re := `\bMath\.abs\s*\(\s*(?:(?:(?:new\s+[\w.]+\s*\([^()]*\)|[\w.]+(?:\([^()]*\))?)\.)?(?:hashCode|nextInt|nextLong)\s*\(\s*\)|(?:Objects\.hash|Arrays\.hashCode|Arrays\.deepHashCode)\s*\([^()]*\))\s*\)`

_bad(_, code) if regex.match(_div_zero, code)

_bad(path, code) if {
	endswith(path, ".java")
	contains(code, "Math.abs")
	regex.match(_abs_re, code)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_lang(path)
	regex.match(`[/%]\s*0|Math\.abs`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[/%]=?\s*0|Math\.abs`, line)
	not _comment(line)
	_bad(path, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Calculation is wrong for every input: an integer division or remainder by literal zero, or Math.abs() of a hash or unbounded random value, which can still be negative. Fix the divisor, or use Math.floorMod / a masked hash",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A line opening with `*name` is a dereferenced assignment target (*pos = ...),
# not the continuation of a block comment (` * text`, ` */`).
_comment(line) if {
	helpers.is_comment_line(line)
	not regex.match(`^\s*\*[A-Za-z_(]`, line)
}

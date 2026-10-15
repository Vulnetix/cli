# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1339

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1339",
	"name": "Insufficient Precision or Accuracy of a Real Number",
	"description": "A floating-point value is compared for exact equality or inequality (==, !=, ===, !==) with a decimal literal that binary floating point cannot represent exactly (0.1, 0.3, 19.99f, 8.99): the computed value is almost never bit-identical to the rounded literal, so the branch silently never (or always) runs, the classic 0.1 + 0.2 != 0.3 money and rate bug. Languages: Python, JavaScript/TypeScript, Java and Go. Not reported: literals that are exact in binary (0.5, 0.25, 1.0, 0.0, 2.75), exponent forms (1e-9), ordering comparisons (<, <=, >, >=), Python doctest lines (>>>), comparisons through a tolerance (math.isclose, pytest.approx, toBeCloseTo, assertAlmostEqual, abs(a - b) < eps), strings such as versions and IP addresses, comments and test files. The rule does not know operand types, so an integer variable compared with a fractional literal is also reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1339/",
	"languages": ["python", "node", "java", "go"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1339],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["float-precision", "floating-point", "correctness", "cwe-1339"],
}

_exts := {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".jsx", ".tsx", ".java", ".go"}

_strip(l) := regex.replace(l, concat("", [`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`, "`[^`]*`"]), `""`)

_strip_comment(path, l) := regex.replace(l, `\s#.*$`, "") if endswith(path, ".py")

_strip_comment(path, l) := regex.replace(l, `\s//.*$`, "") if not endswith(path, ".py")

# literal on the right: x == 0.1 / x !== 0.1 / x != 19.99f
_right_re := `(?:[^=!<>]==|!=)=?\s*\(?\s*[-+]?\d*\.(\d+)[fFdD]?(?:[^\w.]|$)`

# literal on the left: 0.7 == ratio
_left_re := `(?:^|[^\w.])\d*\.(\d+)[fFdD]?\s*(?:===?|!==?)`

_tolerance := `(?i)approx|isclose|closeto|almostequal|assertequals\s*\([^)]*,[^)]*,|math\.abs|\babs\s*\(`

# A decimal fraction with d digits is exact in binary iff 5^d divides it.
_inexact(frac) if count(frac) > 17

_inexact(frac) if {
	d := count(frac)
	d <= 17
	n := to_number(frac)
	pow5 := product([5 | some _ in numbers.range(1, d)])
	n % pow5 != 0
}

_bad(code) if {
	some m in regex.find_all_string_submatch_n(_right_re, code, -1)
	_inexact(m[1])
}

_bad(code) if {
	some m in regex.find_all_string_submatch_n(_left_re, code, -1)
	_inexact(m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
	regex.match(`(?:==|!=)=?\s*\(?\s*[-+]?\d*\.\d|\d\.\d+[fFdD]?\s*(?:==|!=)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "=")
	regex.match(`(?:==|!=)=?\s*\(?\s*[-+]?\d*\.\d|\d\.\d+[fFdD]?\s*(?:==|!=)`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:>>>|\.\.\.)\s`, line)
	code :=_strip(_strip_comment(path, line))
	not regex.match(_tolerance, code)
	_bad(code)
	finding := {
		"rule_id": metadata.id,
		"message": "Exact equality comparison with a decimal literal that floating point cannot represent exactly; the comparison is unreliable. Compare with a tolerance (math.isclose, Math.abs(a - b) < eps) or use a decimal/integer representation (Decimal, BigDecimal, integer cents)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

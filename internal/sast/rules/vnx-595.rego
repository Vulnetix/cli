# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_595

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-595",
	"name": "Boxed number or value object compared by reference (== / !=)",
	"description": "Java's == and != on two objects compare references, not values. This rule reports a comparison whose two operands are both variables declared (as a parameter, local or field within the 60 lines above, including a later declarator such as Long a = x(), b = y()) with a boxed or value type: Integer, Long, Short, Byte, Character, Double, Float, BigDecimal, BigInteger, UUID, Date, LocalDate, LocalDateTime or Instant. Such comparisons pass in tests (the Integer cache covers -128..127) and fail on real values. It also reports an object compared with a freshly constructed wrapper (new Integer(0), new Long(..), new Boolean(..)), which is never identical to anything, and with a boxed X.valueOf(..), unless the other side is a primitive (where Java unboxes and compares values). Not reported: primitives, comparisons with null, enum constants, this, equals/compareTo/Objects.equals, a boxed value against a primitive or a literal, method-call operands whose types are not known, and comments and string literals. String comparison with == is VNX-597.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-595/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [595],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["java", "object-identity", "boxing", "cwe-595"],
}

_obj_types := `(?:Integer|Long|Short|Byte|Character|Double|Float|BigDecimal|BigInteger|UUID|Date|LocalDate|LocalDateTime|Instant)`

_prim_types := `(?:int|long|short|byte|char|double|float|boolean|var)`

_wrappers := `(?:Integer|Long|Short|Byte|Character|Double|Float|Boolean)`

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_msg := "== / != compares object references here, not values: two boxed numbers or value objects are equal only if they are the same instance (the Integer cache hides this for -128..127). Use equals(), Objects.equals() or compareTo()"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?:==|!=)`, content)
	regex.match(concat("", [`\b(?:`, _obj_types, `|new\s+`, _wrappers, `)\b`]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[=!]=`, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	_reports(lines, i, c)
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

# Bare identifier on each side of the operator: not a member (a.b), not a call
# or index (b(), b[0]).
_pairs(c) := [[m[2], m[3]] |
	some m in regex.find_all_string_submatch_n(`(^|[^\w.])([A-Za-z_]\w*)\s*(?:==|!=)\s*([A-Za-z_]\w*)\s*(?:[^\w\s.(\[]|$)`, c, -1)
]

_window(lines, i) := concat("\n", [_code(lines[k]) |
	some k in numbers.range(max([0, i - 60]), i)
	not helpers.is_comment_line(lines[k])
])

_declared_obj(win, v) if {
	regex.match(concat("", [`\b`, _obj_types, `(?:<[^>]*>)?\s+`, v, `\s*[=;,)]`]), win)
	not _declared_prim(win, v)
}

# Long low = a(), high = b(); : a later declarator of the same statement.
_declared_obj(win, v) if {
	regex.match(concat("", [`\b`, _obj_types, `(?:<[^>]*>)?\s+\w+\s*=[^;()]*(?:\([^;()]*\)[^;()]*)*,\s*`, v, `\s*[=;,]`]), win)
	not _declared_prim(win, v)
}

_declared_prim(win, v) if regex.match(concat("", [`\b`, _prim_types, `\s+`, v, `\b`]), win)

_keyword(v) if v in {"null", "this", "true", "false", "super", "class"}

# a == b, both declared as boxed / value types.
_reports(lines, i, c) if {
	some p in _pairs(c)
	not _keyword(p[0])
	not _keyword(p[1])
	p[0] != p[1]
	win := _window(lines, i)
	_declared_obj(win, p[0])
	_declared_obj(win, p[1])
}

# x == new Integer(..) / new Long(..) != x / x == Integer.valueOf(..)
_reports(lines, i, c) if {
	m := regex.find_all_string_submatch_n(concat("", [`([A-Za-z_][\w.]*|\))\s*(?:==|!=)\s*(?:new\s+`, _wrappers, `\s*\(|`, _wrappers, `\.valueOf\s*\()`]), c, -1)
	some mm in m
	_other_not_primitive(lines, i, mm[1])
}

_reports(lines, i, c) if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:new\s+`, _wrappers, `|`, _wrappers, `\.valueOf)\s*\([^()]*\)\s*(?:==|!=)\s*([A-Za-z_][\w.]*)`]), c, -1)
	some mm in m
	_other_not_primitive(lines, i, mm[1])
}

_other_not_primitive(lines, i, v) if {
	not contains(v, ".")
	v != ")"
	not _keyword(v)
	not _declared_prim(_window(lines, i), v)
	_declared_any(_window(lines, i), v)
}

# The other operand is a known non-primitive declaration (Object, a boxed type…).
_declared_any(win, v) if regex.match(concat("", [`\b[A-Z]\w*(?:<[^>]*>)?\s+`, v, `\s*[=;,)]`]), win)

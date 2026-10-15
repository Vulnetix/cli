# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_703

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-703",
	"name": "Optional value read with get() without checking that it is present",
	"description": "An empty Optional is an expected outcome (no row with this id, no element matching the filter), but get()/getAsInt()/getAsLong()/getAsDouble() turns it into an unchecked NoSuchElementException, so a request for an unknown id becomes an HTTP 500 with a stack trace instead of a 404. Reported in production .java files: Spring Data findById(...).get() and derived finders (findByUsername(...).get(), findOneBy...(...).get(), findFirstBy/findTop...(...).get(), which only an Optional-returning repository method makes callable with no argument), Stream findFirst()/findAny() followed by .get() (also with .get() on the next line of a split chain), stream max(...)/min(...).get(), reduce(X::y).get(), IntStream/LongStream/DoubleStream max()/min()/average()/findFirst() followed by getAsInt/getAsLong/getAsDouble, Optional.ofNullable(...).get(), and a variable declared Optional<T> (or OptionalInt/Long/Double), or declared var and assigned from one of those finders or Optional.ofNullable, whose get() is called within the next 15 lines with no isPresent()/isEmpty()/ifPresent()/null test of it in between or on the same line. Not reported: a variable assigned Optional.of(...), which is never empty; orElse/orElseGet/orElseThrow/ifPresent, a presence test before the get(), Map.get, Future.get, List.get, Collections.max(...).get(...), test files, comments and string literals. Optionals passed between methods or stored in fields are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-703/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [703],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-check-exceptional", "optional", "cwe-703"],
}

_args := `\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)`

_get := `\s*\.\s*get\s*\(\s*\)`

_get_as := `\s*\.\s*getAs(?:Int|Long|Double)\s*\(\s*\)`

_inline := [
	concat("", [`\.\s*findById\s*`, _args, _get]),
	# Spring Data derived finders declared to return Optional<T>
	concat("", [`\.\s*(?:findOne\w*|findBy\w+|findFirst\w+|findTop\w*)\s*`, _args, _get]),
	concat("", [`\.\s*(?:findFirst|findAny)\s*\(\s*\)`, _get]),
	concat("", [`\)\s*\.\s*(?:max|min)\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))+\)`, _get]),
	concat("", [`\.\s*reduce\s*\(\s*[\w.]+::\w+\s*\)`, _get]),
	concat("", [`\)\s*\.\s*(?:max|min|average|findFirst|findAny)\s*\(\s*\)`, _get_as]),
	concat("", [`\bOptional\s*\.\s*(?:ofNullable|empty)\s*`, _args, _get]),
]

# A chain split over lines: `.findFirst()` ends one line, `.get()` starts the next.
_split_tail := `(?:\.\s*(?:findFirst|findAny)\s*\(\s*\)|\.\s*findById\s*\(.*\)|\)\s*\.\s*(?:max|min|average)\s*\(.*\))\s*$`

_split_head := `^\s*\.\s*(?:get|getAs(?:Int|Long|Double))\s*\(\s*\)`

_decl := `^\s*(?:final\s+)?(?:java\.util\.)?Optional(?:Int|Long|Double)?\s*(?:<[^;=]*>)?\s+([A-Za-z_]\w*)\s*=`

# Optional.of(x) is never empty.
_opt_var(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_decl, line, 1)
	count(m) > 0
	not regex.match(`=\s*(?:java\.util\.)?Optional\s*\.\s*of\s*\(`, line)
}

# var x = repo.findById(id); / var x = stream.filter(...).findFirst();
_opt_var(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(?:final\s+)?var\s+([A-Za-z_]\w*)\s*=.*(?:\.\s*(?:findById|findOne\w*|findBy\w+|findFirst\w*|findAny|findTop\w*)|\bOptional\s*\.\s*ofNullable)\s*`, _args, `\s*;\s*$`]), line, 1)
	count(m) > 0
}

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_msg := "Optional.get() throws NoSuchElementException when the value is absent; use orElseThrow() with a meaningful exception, orElse(), or test isPresent() first"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`\.\s*get(?:As(?:Int|Long|Double))?\s*\(\s*\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "get")
	not helpers.is_comment_line(line)
	_inline_hit(lines, i, _code(line))
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

_inline_hit(_, _, code) if {
	some re in _inline
	regex.match(re, code)
}

_inline_hit(lines, i, code) if {
	regex.match(_split_head, code)
	ks := [k | some k in numbers.range(max([0, i - 3]), i - 1); trim_space(lines[k]) != ""; not helpers.is_comment_line(lines[k])]
	count(ks) > 0
	regex.match(_split_tail, _code(lines[ks[count(ks) - 1]]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`Optional|\bvar\s`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Optional|\bvar\s`, line)
	not helpers.is_comment_line(line)
	v := _opt_var(_code(line))
	use_re := concat("", [`\b`, v, `\s*\.\s*(?:get|getAs(?:Int|Long|Double))\s*\(\s*\)`])
	guard_re := concat("", [`\b`, v, `\s*\.\s*(?:isPresent|isEmpty|ifPresent\w*)\s*\(|\b`, v, `\s*[!=]=\s*null|\bnull\s*[!=]=\s*`, v, `\b`])
	uses := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
		not helpers.is_comment_line(lines[k])
		regex.match(use_re, _code(lines[k]))
	]
	count(uses) > 0
	j := uses[0]
	not _guarded(lines, i, j, guard_re)
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

_guarded(lines, i, j, guard_re) if {
	some k in numbers.range(i + 1, j)
	not helpers.is_comment_line(lines[k])
	regex.match(guard_re, lines[k])
}

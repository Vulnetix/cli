# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_396

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-396",
	"name": "Declaration of Catch for Generic Exception",
	"description": "A catch of the generic exception type that then throws away what was caught: Java catch (Exception e), catch (RuntimeException e) or catch (Throwable t) (final and java.lang. forms included), and C# catch (Exception), catch (Exception ex) and a bare catch, whose body neither rethrows nor references the caught exception (no log, wrap or record of it), so every failure, including unrelated programming errors, is converted into the same default (return null, return false, a flag). Not reported: a generic catch that logs, wraps, records or rethrows the exception (throw; or throw e), a catch of a specific type, a variable named ignored/ignore/expected/unused, an empty Java catch body (VNX-391 reports that), test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-396/",
	"languages": ["java", "csharp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [396],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["error-handling", "cwe-396"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

# group 1: the variable (may be empty in C#), group 2: the rest of the line.
_catch_re(path) := `\bcatch\s*\(\s*(?:final\s+)?(?:java\.lang\.)?(?:Exception|RuntimeException|Throwable)\s+(\w+)\s*\)(.*)$` if endswith(path, ".java")

_catch_re(path) := `\bcatch\s*(?:\(\s*(?:System\.)?Exception(?:\s+(\w+))?\s*\))?\s*((?:\{.*)?)$` if endswith(path, ".cs")

_discard_var(v) if regex.match(`^(?i:ignored?|expected|unused|_+)$`, v)

# One-line body: catch (...) { ... }
_body(lines, i, rest) := b if {
	regex.match(`^\s*\{.*\}`, rest)
	b := regex.replace(regex.replace(rest, `^\s*\{`, ""), `\}[^}]*$`, "")
}

# Multi-line body: lines up to the closing brace at the catch's indent.
_body(lines, i, rest) := b if {
	not regex.match(`^\s*\{.*\}`, rest)
	ic := _indent(lines[i])
	ends := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 25]))
		k > i
		_indent(lines[k]) <= ic
		startswith(trim_space(lines[k]), "}")
	]
	count(ends) > 0
	b := concat("\n", [l |
		some k in numbers.range(i + 1, ends[0])
		k < ends[0]
		l := lines[k]
		not helpers.is_comment_line(l)
		trim_space(l) != "{"
	])
}

findings contains finding if {
	some path, content in input.file_contents
	re := _catch_re(path)
	contains(content, "catch")
	not helpers.is_test_path(path)
	not regex.match(`(?:^|/)[^/]*Tests?\.cs$`, path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "catch")
	not helpers.is_comment_line(line)
	ms := regex.find_all_string_submatch_n(re, _strip_strings(line), 1)
	count(ms) > 0
	v := ms[0][1]
	not _discard_var(v)
	body := _body(lines, i, ms[0][2])
	_reportable_body(path, body)
	not regex.match(`\bthrow\b`, body)
	not _uses(body, v)
	finding := {
		"rule_id": metadata.id,
		"message": "Generic exception caught and discarded: every failure, including unrelated bugs, becomes the same default result and the cause is lost. Catch the specific exceptions the call throws, or log/rethrow the caught one",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java empty bodies belong to VNX-391.
_reportable_body(path, body) if trim_space(body) != ""

_reportable_body(path, body) if {
	trim_space(body) == ""
	endswith(path, ".cs")
}

_uses(body, v) if {
	v != ""
	regex.match(concat("", [`\b`, v, `\b`]), body)
}

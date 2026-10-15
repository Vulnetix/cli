# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_167

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-167",
	"name": "Improper Handling of Additional Special Element",
	"description": "A key=value or name:secret string is split on every '=' or ':' and the pieces are unpacked into a fixed number of names, so an additional separator in the value is mishandled: Python 'k, v = s.split(\"=\")' (also through map(str.strip, ...) or a generator, 'for k, v in (p.split(\"=\") for p in ...)' and dict(x.split(\"=\") for x in ...)) raises ValueError on 'token=abc=', and JavaScript/TypeScript 'const [user, pass] = s.split(\":\")' (with or without a limit, an elided first element '[, pass]', or a trailing .map(...)) silently drops everything after the second separator, truncating a password, a base64 value or an IPv6 address. Not reported: a bounded split (split(sep, 1), maxsplit=1, rsplit(sep, 1)), str.partition, a regex split, a rest element ([k, ...rest]), a single destructured name, a split kept as a list, hours/minutes clock parsing, other separators, an unpack inside a try block, test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-167/",
	"languages": ["python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [167],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["additional-special-element", "parsing", "cwe-167"],
}

_sep := `(?:"[=:]"|'[=:]')`

_py_unpack := concat("", [`^\s*\(?\s*[A-Za-z_]\w*\s*(?:,\s*[A-Za-z_]\w*\s*)+,?\s*\)?\s*=\s*[^=].*\.split\(\s*`, _sep, `\s*\)[\s)]*(?:#.*)?$`])

_py_dict := concat("", [`\bdict\s*\(.*\.split\(\s*`, _sep, `\s*\)\s+for\s`])

# for k, v in (pair.split("=") for pair in ...), also inside a comprehension.
_py_for := concat("", [`\bfor\s+\(?\s*[A-Za-z_]\w*\s*(?:,\s*[A-Za-z_]\w*\s*)+\)?\s+in\s+\(\s*[\w.\[\]()]+\.split\(\s*`, _sep, `\s*\)\s+for\s`])

_js_sep := concat("", [`(?:"[=:]"|'[=:]'|`, "`[=:]`", `)`])

# [a, b], and an elided first element ([, password]); a trailing .map(...) keeps the arity.
_js_unpack := concat("", [`^\s*(?:(?:const|let|var)\s+)?\[\s*(?:[A-Za-z_$][\w$]*\s*)?(?:,\s*(?:[A-Za-z_$][\w$]*\s*)?)*,\s*[A-Za-z_$][\w$]*\s*\]\s*(?::\s*[^=]+)?=\s*[^=].*\.split\(\s*`, _js_sep, `\s*(?:,\s*\d+\s*)?\)(?:\s*\.map\(.*\))?\s*;?\s*$`])

# "HH:MM" clock parsing: dropping or rejecting seconds is the intent.
_time_fields(line) if regex.match(`(?i)[\[(,\s](?:h|hh|hours?|hrs?)\s*,\s*(?:m|mm|mins?|minutes?)\s*[\]),=]`, line)

_lang_re(path) := [_py_unpack, _py_dict, _py_for] if endswith(path, ".py")

_lang_re(path) := [_js_unpack] if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_in_string(line) if {
	idx := indexof(line, ".split(")
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	count(regex.find_n(`"`, pre, -1)) % 2 == 1
}

_in_string(line) if {
	idx := indexof(line, ".split(")
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	count(regex.find_n(`'`, pre, -1)) % 2 == 1
}

# Python: the unpack sits in a try block that handles the ValueError.
_guarded(lines, i) if {
	some j in numbers.range(max([0, i - 2]), i - 1)
	regex.match(`^\s*try\s*:`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	res := _lang_re(path)
	contains(content, ".split(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".split(")
	not helpers.is_comment_line(line)
	some re in res
	regex.match(re, line)
	not _in_string(line)
	not _time_fields(line)
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The value is split on every separator and unpacked into a fixed number of names; an additional '=' or ':' in the value raises an error (Python) or truncates it (JavaScript). Split once: s.split(sep, 1) / s.partition(sep), or s.slice(s.indexOf(sep) + 1)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

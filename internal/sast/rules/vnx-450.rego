# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_450

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-450",
	"name": "Multiple interpretations of input: a text flag read as a boolean by truthiness",
	"description": "Reports a configuration or request flag that arrives as text and is turned into a boolean by truthiness, so every non-empty answer, including \"false\", \"0\" and \"no\", reads as on: Python bool() around os.environ/os.getenv, a Flask or Django request parameter (directly or through a variable assigned from one in the six lines above), sys.argv or input(); Python os.environ.get/os.getenv with a True/False default (set to anything, the value is a non-empty string and truthy); argparse add_argument(..., type=bool), under which --flag False is True; Node Boolean() or !! around process.env or req.query; and Node process.env.X || true/false or ?? true/false. bool()/Boolean()/!! are reported only when the line names a switch (debug, enable, disable, allow, skip, require, verify, enforce, strict, insecure, secure, tls, ssl, csrf, auth, admin, public, private, include, notify, verbose, force, dry-run, beta, feature, flag), because bool() of a token, URL or path is a deliberate is-it-set test; input() is always reported. Not reported: values parsed explicitly (strtobool, == / !=, in (...), .lower(), int()), string defaults, bool() of ordinary values, comments, string literals, docstrings and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-450/",
	"languages": ["python", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [450],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["multiple-interpretations", "truthiness", "configuration", "cwe-450"],
}

_py_src := `(?:\bos\.environ\.get\(|\bos\.environ\[|\bos\.getenv\(|(?:^|[^\w.])environ(?:\.get\(|\[)|(?:^|[^\w.])getenv\(|\brequest\.(?:args|form|values|GET|POST|query_params|headers|cookies)(?:\.get\(|\[)|\bsys\.argv\[)`

_py_bool := concat("", [`\bbool\(\s*`, _py_src])

_py_input := `\bbool\(\s*input\(`

_py_bool_var := `\bbool\(\s*([A-Za-z_]\w*)\s*\)`

_py_env_default := `(?:\bos\.environ\.get|\bos\.getenv|(?:^|[^\w.])environ\.get|(?:^|[^\w.])getenv)\(\s*[^,()]+,\s*(?:True|False)\s*\)`

_js_bool := `\bBoolean\(\s*(?:process\.env(?:\.\w+|\[)|req(?:uest)?\.query(?:\.\w+|\[))`

_js_bang := `!!\s*\(?\s*(?:process\.env(?:\.\w+|\[)|req(?:uest)?\.query(?:\.\w+|\[))`

_js_default :=`\bprocess\.env(?:\.\w+|\[[^\]]+\])\s*(?:\|\||\?\?)\s*(?:true|false)\b`

_switch := `(?i)debug|enabl|disabl|allow|skip|requir|verif|enforc|strict|insecur|secure|verbose|force|dry_?run|public|private|admin|notify|include|beta|feature|flag|tls|ssl|csrf|signup|anonym|auth`

_value_name := `(?i)token|secret|passw|dsn|_url\b|_uri\b|_path\b|_dir\b|_file\b`

_parsed := `(?i)strtobool|str2bool|to_bool|parse_?bool|json\.loads|literal_eval|==|!=|\bin\s*[(\[{]|\.lower\(|\bint\(`

_names_switch(text) if {
	regex.match(_switch, text)
	not regex.match(_value_name, text)
}

# The match starts inside a string literal: an odd number of quotes before it.
_in_string(line, re) if {
	prefix := regex.replace(line, concat("", ["(?:", re, ").*$"]), "")
	some q in [`"`, `'`, "`"]
	count(regex.find_n(q, prefix, -1)) % 2 == 1
}

# Inside a Python docstring: an odd number of triple quotes above the line.
_in_docstring(lines, i) if {
	above := concat("\n", array.slice(lines, 0, i))
	count(regex.find_n(`"""|'''`, above, -1)) % 2 == 1
}

# The statement starting at i, joined with the next line when its call is
# still open.
_stmt(lines, i) := s if {
	count(regex.find_n(`\(`, lines[i], -1)) > count(regex.find_n(`\)`, lines[i], -1))
	i + 1 < count(lines)
	s := concat(" ", [lines[i], lines[i + 1]])
} else := lines[i]

_py_is("bool", lines, i, line) if {
	regex.match(_py_bool, line)
	not _in_string(line, _py_bool)
	_names_switch(line)
}

_py_is("input", lines, i, line) if {
	regex.match(_py_input, line)
	not _in_string(line, _py_input)
}

_py_is("bool", lines, i, line) if {
	not regex.match(_py_bool, line)
	some m in regex.find_all_string_submatch_n(_py_bool_var, line, -1)
	v := m[1]
	some j in numbers.range(max([0, i - 6]), i - 1)
	helpers.assigned_first(lines[j]) == v
	regex.match(_py_src, lines[j])
	not regex.match(_parsed, lines[j])
	_names_switch(concat(" ", [lines[j], line]))
}

# argparse add_argument(..., type=bool): bool("False") is True, so --flag False
# turns the option on. The call may start up to three lines above.
_py_is("argtype", lines, i, line) if {
	regex.match(`\btype\s*=\s*bool\b`, line)
	not _in_string(line, `\btype\s*=\s*bool\b`)
	regex.match(`\badd_argument\s*\(`, helpers.code_window(lines, i, 3, 0))
}

_py_is("default", lines, i, line) if {
	stmt := _stmt(lines, i)
	regex.match(_py_env_default, stmt)
	not _in_string(line, `\b(?:environ|getenv)`)
	not regex.match(_parsed, stmt)
}

_js_is("bool", line) if {
	regex.match(_js_bool, line)
	not _in_string(line, _js_bool)
	_names_switch(line)
}

_js_is("bool", line) if {
	regex.match(_js_bang, line)
	not _in_string(line, _js_bang)
	_names_switch(line)
}

_js_is("default", line) if {
	regex.match(_js_default, line)
	not _in_string(line, _js_default)
	not regex.match(_parsed, line)
}

_message(k) := "argparse type=bool calls bool() on the argument text, so --flag False and --flag 0 both turn the option on. Use action=\"store_true\"/argparse.BooleanOptionalAction or an explicit parser" if {
	k == "argtype"
} else := "bool(input(...)) is True for every non-empty answer, including \"no\": the prompt's answer is never read. Compare the answer with the accepted words" if {
	k == "input"
} else :="A flag that arrives as text is read by truthiness, so \"false\", \"0\" and \"no\" all mean on. Parse it explicitly (value.strip().lower() in {\"1\", \"true\", \"yes\"})"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`\bbool\(|\btype\s*=\s*bool\b|(?:environ\.get|getenv)\([^)]*,\s*(?:True|False)\s*\)|environ\.get\(\s*$|getenv\(\s*$`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bbool\b|environ|getenv`, line)
	not helpers.is_comment_line(line)
	kinds := {k | some k in ["argtype", "bool", "default", "input"]; _py_is(k, lines, i, line)}
	count(kinds) > 0
	not _in_docstring(lines, i)
	kind := min(kinds)
	finding := {
		"rule_id": metadata.id,
		"message": _message(kind),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)
	not helpers.is_test_path(path)
	regex.match(`\bBoolean\(\s*(?:process\.env|req)|!!\s*\(?\s*(?:process\.env|req)|process\.env\S*\s*(?:\|\||\?\?)\s*(?:true|false)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Boolean\(|process\.env`, line)
	not helpers.is_comment_line(line)
	kinds := {k | some k in ["bool", "default"]; _js_is(k, line)}
	count(kinds) > 0
	finding := {
		"rule_id": metadata.id,
		"message": _message(min(kinds)),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

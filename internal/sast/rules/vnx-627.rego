# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_627

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-627",
	"name": "Dynamic Variable Evaluation",
	"description": "A variable whose NAME comes from the request is read or written, so the client chooses which of the program's variables it reads or overwrites ($is_admin, a configuration global, an instance variable holding the current user). Reported: Python globals()/locals()/vars() indexed (or read with .get/.pop/.setdefault) by a request value (request.args/form/values/json/GET/POST/data/cookies/headers/query_params), or globals()/locals()/vars(x)/x.__dict__ .update() with request data; Ruby instance_variable_set/get, class_variable_set/get and binding.local_variable_set/get whose name argument interpolates params, cookies or request parameters; PHP variable variables ($$name, ${$name}, ${$_GET[...]}) whose name is a superglobal or a variable assigned from one; JavaScript global[...]/globalThis[...]/window[...] (the bare global object, not a property such as config.global) indexed by req.query/body/params/cookies/headers. The request value may be inline or reach the sink through a variable assigned (or a for/each loop variable bound) from it in the 10 lines above. Not reported: constant names, names from function parameters or configuration (no cross-function dataflow), ordinary dictionary or object lookups, PHP variable variables in a foreach over a superglobal and extract() (VNX-PHP-007 reports those), and the sinks inside comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-627/",
	"languages": ["python", "ruby", "php", "node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [627],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["dynamic-variable", "variable-variables", "cwe-627"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "js" if {
	some ext in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
}

# Whole-file gates: the file names a sink at all.
_gate := {
	"py": `globals\(\)|locals\(\)|vars\(|__dict__\.update`,
	"rb": `_variable_(set|get)`,
	"php": `\$\$|\$\{\s*\$`,
	"js": `\b(global|globalThis|window)\s*\[`,
}

_source := {
	"py": `\brequest\.(args|form|values|json|get_json|GET|POST|data|cookies|headers|query_params|params)\b`,
	"rb": `\b(params|cookies)\s*(\[|\.(fetch|require|permit|to_unsafe_h|each))|\brequest\.(params|query_parameters|request_parameters)\b`,
	"php": `\$_(GET|POST|REQUEST|COOKIE)\b`,
	"js": `\breq(uest)?\.(query|body|params|cookies|headers)\b`,
}

# The expression that names the variable, captured from the code line.
_sink := {
	"py": [
		`\b(?:globals|locals|vars)\(\)\s*\[([^\]]+)\]`,
		`\b(?:globals|locals|vars)\(\)\.(?:get|pop|setdefault)\(\s*([^,)]+)`,
		`\b(?:globals|locals)\(\)\.update\((.+)\)`,
		`\bvars\([^()]*\)\.update\((.+)\)`,
		`\.__dict__\.update\((.+)\)`,
	],
	"rb": [`\b(?:instance_variable_set|instance_variable_get|class_variable_set|class_variable_get|local_variable_set|local_variable_get)\s*\(?\s*([^,)]+)`],
	"php": [`\$\$([A-Za-z_]\w*)`, `\$\{\s*(\$[^}]+)\}`],
	"js": [`(?:^|[^\w.$])(?:global|globalThis|window)\s*\[([^\]]+)\]`],
}

# String literals blanked, so the sink must be code. Ruby and PHP names are
# read from the raw line, where interpolation ("@#{params[:k]}") lives.
_blank(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_keys(lang, raw, code) := ks if {
	lang in {"py", "js"}
	ks := {g[1] |
		some re in _sink[lang]
		some g in regex.find_all_string_submatch_n(re, code, -1)
	}
}

_keys(lang, raw, code) := ks if {
	lang in {"rb", "php"}
	ks := {g[1] |
		some re in _sink[lang]
		regex.match(re, code)
		some g in regex.find_all_string_submatch_n(re, raw, -1)
	}
}

# Names bound from the request in the lines above: assignment, JavaScript
# destructuring, a Python for loop and a Ruby each block.
_tainted(lang, lines, i) := helpers.tainted_names(lines, i, 10, _source[lang])

_bound(lang, lines, i) := {v |
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	regex.match(_source[lang], l)
	not helpers.is_comment_line(l)
	some re in [
		`^\s*(?:const|let|var)\s*\{\s*([A-Za-z_$][\w$]*)`,
		`^\s*for\s+([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)?\s+in\s`,
		`\.each(?:_pair)?\s*(?:do\s*)?\{?\s*\|\s*([A-Za-z_]\w*)`,
		`^\s*\$([A-Za-z_]\w*)\s*=[^=]`,
	]
	m := regex.find_all_string_submatch_n(re, l, 1)
	count(m) > 0
	v := m[0][1]
}

_from_request(lang, _, _, k) if regex.match(_source[lang], k)

_from_request(lang, lines, i, k) if {
	names := _tainted(lang, lines, i) | _bound(lang, lines, i)
	some v in names
	_names(lang, k, v)
}

_names("php", k, v) if regex.match(concat("", [`^\$?`, v, `\b`]), trim_space(k))

_names(lang, k, v) if {
	lang != "php"
	regex.match(concat("", [`(^|[^\w$.])`, v, `\b`]), k)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	some k in _keys(lang, line, _blank(line))
	_from_request(lang, lines, i, k)
	finding := {
		"rule_id": metadata.id,
		"message": "A variable whose name comes from the request is read or written: the client chooses which program variable it reads or overwrites. Map allowed names to values explicitly instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

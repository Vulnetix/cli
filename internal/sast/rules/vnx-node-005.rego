package vulnetix.rules.vnx_node_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-005",
	"name": "innerHTML or dangerouslySetInnerHTML usage",
	"description": "HTML is written into the DOM from a value that is not a constant: an assignment (= or +=) to .innerHTML or .outerHTML (also el[\"innerHTML\"]), insertAdjacentHTML(position, html) (also with its arguments on the following lines), document.write/writeln(html), or a React dangerouslySetInnerHTML={{ __html: value }} (also across line breaks), where the value is a variable, a call, concatenation or a template literal with ${...} interpolation (including one spanning several lines). If any part of it is user-controlled this is cross-site scripting. Not reported: string literals without interpolation, null/number/boolean literals, ALL_CAPS constants, copying another element's innerHTML, values passed through DOMPurify.sanitize, sanitize-html or an escape/encode function, reads and comparisons of innerHTML, textContent/innerText, comments and string literals, minified files. Overlaps VNX-NODE-012 and VNX-NODE-027, which match the same sinks less strictly.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-005/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["xss", "web", "react"],
}

_is_js(path) if regex.match(`\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$`, path)

_file_gate := `innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML`

# A template literal with interpolation becomes the identifier tpl_x; every
# other complete string literal collapses to "".
_strip(line) := regex.replace(
	regex.replace(line, `\x60(?:[^\x60\\]|\\.)*\$\{(?:[^\x60\\]|\\.)*\x60`, "tpl_x"),
	`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60`, `""`,
)

_sinks := [
	{"re": `\.(?:inner|outer)HTML\s*\+?=(?:[^=](.*))?$`, "what": "innerHTML/outerHTML assignment", "split": false},
	{"re": `\.insertAdjacentHTML\s*\(\s*""\s*,(.*)$`, "what": "insertAdjacentHTML()", "split": false},
	{"re": `\.insertAdjacentHTML\s*\(\s*()$`, "what": "insertAdjacentHTML()", "split": true},
	{"re": `(?:^|[^\w$.])document\.write(?:ln)?\s*\((.*)$`, "what": "document.write()", "split": false},
	{"re": `dangerouslySetInnerHTML\s*[=:]\s*\{\s*\{?\s*(.*)$`, "what": "dangerouslySetInnerHTML", "split": false},
]

_sanitizer_re := `(?i)sanitiz|purify|escape|encode|\bxss\s*\(|\bhe\.`

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	not _vendored(path)
	regex.match(_file_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_file_gate, line)
	count(line) <= 400
	not helpers.is_comment_line(line)
	s := _strip(_norm(line))
	some sink in _sinks
	m := regex.find_all_string_submatch_n(sink.re, s, 1)
	count(m) > 0
	v := _sink_value(lines, i, sink, m[0][1])
	_dynamic(v)
	not regex.match(_sanitizer_re, v)
	not _tpl_sanitized(line, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s with a non-constant value can lead to XSS; set textContent, or sanitize the HTML with DOMPurify.sanitize() first", [sink.what]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# el["innerHTML"] = x is el.innerHTML = x.
_norm(line) := regex.replace(line, `\[\s*['"]((?:inner|outer)HTML)['"]\s*\]`, ".$1") if contains(line, "HTML")

_norm(line) := line if not contains(line, "HTML")

_sink_value(lines, i, sink, rest) := _value(lines, i, rest) if not sink.split

# insertAdjacentHTML( broken after its parenthesis: the position is on the
# next line, and the HTML follows it there or on the line after.
_sink_value(lines, i, sink, _) := v if {
	sink.split
	i + 1 < count(lines)
	pm := regex.find_all_string_submatch_n(`^\s*""\s*,(.*)$`, _strip(lines[i + 1]), 1)
	count(pm) > 0
	v := _value(lines, i + 1, pm[0][1])
}

# The value written, with the __html: key of a React prop removed. A call
# broken right after its opening brace or the = continues on the next line;
# a template literal left open is followed until it closes.
_value(lines, i, rest) := v if {
	trim_space(rest) != ""
	not _open_template(rest)
	v := regex.replace(rest, `^\s*__html\s*:`, "")
}

_value(lines, i, rest) := v if {
	trim_space(rest) == ""
	i + 1 < count(lines)
	v := regex.replace(_strip(lines[i + 1]), `^\s*(?:\{\s*)?__html\s*:`, "")
}

_value(lines, i, rest) := "tpl_x" if {
	_open_template(rest)
	tail := concat("\n", array.slice(lines, i + 1, i + 20))
	m := regex.find_all_string_submatch_n(`^[^\x60]*`, tail, 1)
	contains(m[0][0], "${")
}

_value(lines, i, rest) := `""` if {
	_open_template(rest)
	tail := concat("\n", array.slice(lines, i + 1, i + 20))
	m := regex.find_all_string_submatch_n(`^[^\x60]*`, tail, 1)
	not contains(m[0][0], "${")
}

_open_template(rest) if regex.match(`^\s*(?:__html\s*:\s*)?\x60[^\x60]*$`, rest)

# Up to the end of the expression, anything but string literals, an ALL_CAPS
# constant, or another element's innerHTML.
_dynamic(v) if {
	head := regex.replace(v, `\}\}.*$|;.*$`, "")
	not regex.match(`^\s*\(?\s*(?:[\w$]+\.)*[A-Z][A-Z0-9_]*\s*\)?\s*[,)]?\s*$`, head)
	not regex.match(`^\s*[\w$.\[\]()"]+\.(?:inner|outer)HTML\s*$`, head)
	not regex.match(`^\s*(?:null|undefined|true|false|-?\d+(?:\.\d+)?)\s*[,)]?\s*$`, head)
	regex.match(`[\w$]`, regex.replace(head, `""`, ""))
}

# A one-line template literal whose every ${...} interpolation is passed
# through an escape/encode/sanitize function writes no raw value.
_tpl_sanitized(line, v) if {
	regex.match(`^\s*tpl_x\s*\)?\s*;?\s*$`, v)
	interps := regex.find_all_string_submatch_n(`\$\{([^}]*)\}`, line, -1)
	count(interps) > 0
	every x in interps {
		regex.match(`^\s*(?:[\w$]+\.)*[\w$]*(?i:sanitiz|purify|escape|encode)[\w$]*\s*\(`, x[1])
	}
}

# Vendored third-party libraries (jQuery, editors, plugins) are not the
# application's sinks.
_vendored(path) if regex.match(`(^|/)(vendors?|libs|third[_-]?party|bower_components|plugins)/`, path)

_vendored(path) if regex.match(`(^|/)jquery[\w.-]*\.js$`, path)

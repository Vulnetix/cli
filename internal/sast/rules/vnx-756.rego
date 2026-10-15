# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_756

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-756",
	"name": "Framework traceback page served instead of a custom error page",
	"description": "A Python web application is configured so that an unhandled exception is answered with the framework's own debug error page (stack trace, source lines, local variables, request and settings) rather than a custom error page. Reported: FastAPI(..., debug=True) and Starlette(..., debug=True); in a file that imports tornado, debug=True or serve_traceback=True as an Application keyword or a \"debug\"/\"serve_traceback\": True settings entry; in a file that imports bottle, bottle.debug(True), debug(True) and run(..., debug=True); in a file that imports cherrypy, a 'request.show_tracebacks': True config entry; in a file that imports sanic or quart, <app>.run(..., debug=True); and web.py's web.config.debug = True and app.internalerror = web.debugerror. A call broken over several lines is read up to eight lines on. Not reported: debug taken from an environment variable, a setting or a command-line flag, debug=False, test code, comments and string literals. Flask's debugger is VNX-PY-008 and Django's DEBUG = True is VNX-PY-006; whether an application registers its own 500 handler is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-756/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [756],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-custom-error", "debug-mode", "python", "cwe-756"],
}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# Keep dictionary keys: "debug": True is code, not prose.
_code_keys(line) := regex.replace(line, `#.*$`, "")

_imports(content, mod) if regex.match(concat("", [`(?m)^\s*(import|from)\s+`, mod, `\b`]), content)

# The call opened on line i, joined with following lines until it closes
# (bounded to eight lines).
_call_text(lines, i) := t if {
	end := min([count(lines) - 1, i + 8])
	t := concat(" ", [_code(lines[k]) | some k in numbers.range(i, end)])
}

_debug_kw := `\bdebug\s*=\s*True\b`

_kw_in_call(lines, i, open_re) if {
	t := _call_text(lines, i)
	m := regex.find_all_string_submatch_n(concat("", [open_re, `\s*\(((?:[^()]|\([^()]*\))*)\)`]), t, 1)
	count(m) > 0
	regex.match(_debug_kw, m[0][1])
}

_flag(_, lines, i) if {
	regex.match(`\b(FastAPI|Starlette)\s*\(`, _code(lines[i]))
	_kw_in_call(lines, i, `\b(?:FastAPI|Starlette)`)
}

_flag(content, lines, i) if {
	_imports(content, "tornado")
	regex.match(`\b(debug|serve_traceback)\s*=\s*True\b|["'](debug|serve_traceback)["']\s*:\s*True\b`, _code_keys(lines[i]))
	not regex.match(`^\s*(define|options\.define)\s*\(`, lines[i])
}

_flag(content, lines, i) if {
	_imports(content, "bottle")
	regex.match(`(^|[^\w.]|\bbottle\.)debug\s*\(\s*True\s*\)`, _code(lines[i]))
}

_flag(content, lines, i) if {
	_imports(content, "bottle")
	regex.match(`(^|[^\w.]|\b\w+\.)run\s*\(`, _code(lines[i]))
	_kw_in_call(lines, i, `\brun`)
}

_flag(content, lines, i) if {
	_imports(content, "cherrypy")
	regex.match(`["']request\.show_tracebacks["']\s*:\s*True\b`, _code_keys(lines[i]))
}

_flag(content, lines, i) if {
	regex.match(`(?m)^\s*(import|from)\s+(sanic|quart)\b`, content)
	regex.match(`\b\w+\.run\s*\(`, _code(lines[i]))
	_kw_in_call(lines, i, `\.run`)
}

_flag(content, lines, i) if {
	_imports(content, "web")
	regex.match(`\bweb\.config\.debug\s*=\s*True\b|\.internalerror\s*=\s*web\.debugerror\b`, _code(lines[i]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`debug\s*=\s*True|debug\(\s*True|(debug|serve_traceback|show_tracebacks)["']\s*:\s*True|serve_traceback\s*=\s*True|internalerror`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_line_gate(line)
	not helpers.is_comment_line(line)
	_flag(content, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The framework's debug error page (stack trace, source, local variables) is served for unhandled exceptions instead of a custom error page. Turn debug off in deployed configuration and register a generic error handler",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_line_gate(line) if contains(line, "True")

_line_gate(line) if contains(line, "debugerror")

_line_gate(line) if contains(line, "FastAPI(")

_line_gate(line) if contains(line, "Starlette(")

_line_gate(line) if contains(line, "run(")

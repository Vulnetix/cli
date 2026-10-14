package vulnetix.rules.vnx_py_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-008",
	"name": "Flask debug mode enabled",
	"description": "The Werkzeug interactive debugger is switched on in a Flask or Werkzeug application's code, so an exception page offers a Python console to whoever triggers it (the debugger PIN is guessable from host facts and has been bypassed): run(..., debug=True) on a Flask application object (a name assigned from Flask(...) or SocketIO(...), app, application, or create_app()), with the keyword anywhere in a call broken over several lines; <app>.debug = True; <app>.config[\"DEBUG\"] = True and <app>.config.update(DEBUG=True); werkzeug run_simple(..., use_debugger=True); and DebuggedApplication(..., evalex=True). Files must import flask or werkzeug. Not reported: debug driven by an environment variable or set to False, run(debug=True) on other objects (task.run, uvicorn.run), class attributes named debug, test files, and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-008/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [489],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["flask", "debug", "config", "rce"],
}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# Names that hold the Flask application (or its SocketIO wrapper).
_apps(content) := {"app", "application"} | {m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*([A-Za-z_]\w*)\s*(?::\s*[\w.]+\s*)?=\s*(?:flask\.)?(?:Flask|SocketIO)\s*\(`, content, -1)
}

_depth(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

_close_index(lines, i, rest) := k if {
	end := min([count(lines) - 1, i + 8])
	end >= i + 1
	d0 := _depth(rest) + 1
	ks := [j |
		some j in numbers.range(i + 1, end)
		d0 + sum([_depth(_code(lines[x])) | some x in numbers.range(i + 1, j)]) <= 0
	]
	count(ks) > 0
	k := ks[0]
}

_call_text(_, _, rest) := rest if _depth(rest) < 0

_call_text(lines, i, rest) := rest if {
	_depth(rest) >= 0
	not _close_index(lines, i, rest)
}

_call_text(lines, i, rest) := txt if {
	_depth(rest) >= 0
	k := _close_index(lines, i, rest)
	more := [_code(lines[j]) | some j in numbers.range(i + 1, k); not helpers.is_comment_line(lines[j])]
	txt := concat("\n", array.concat([rest], more))
}

# app.run(..., debug=True)
_debug_on(lines, i, c, apps) := "run(debug=True)" if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])([A-Za-z_]\w*)(\(\))?\.run\s*\((.*)$`, c, 1)
	count(m) > 0
	_app_ref(m[0][1], m[0][2], apps)
	args := _call_text(lines, i, m[0][3])
	regex.match(`\bdebug\s*=\s*True\b`, args)
	not regex.match(`\buse_debugger\s*=\s*False\b`, args)
}

# app.debug = True
_debug_on(_, _, c, apps) := "debug = True" if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\.debug\s*=\s*True\b`, c, 1)
	count(m) > 0
	m[0][1] in apps
}

# app.config["DEBUG"] = True, read from the raw line (the key is a string).
_debug_on(lines, i, _, apps) := "config DEBUG = True" if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\.config\s*\[\s*["']DEBUG["']\s*\]\s*=\s*True\b`, lines[i], 1)
	count(m) > 0
	m[0][1] in apps
}

_debug_on(lines, i, c, apps) := "config DEBUG=True" if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])([A-Za-z_]\w*)\.config\.(?:update|from_mapping)\s*\((.*)$`, c, 1)
	count(m) > 0
	m[0][1] in apps
	regex.match(`\bDEBUG\s*=\s*True\b`, _call_text(lines, i, m[0][2]))
}

_debug_on(lines, i, c, _) := "run_simple(use_debugger=True)" if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])(?:werkzeug\.serving\.)?run_simple\s*\((.*)$`, c, 1)
	count(m) > 0
	regex.match(`\buse_debugger\s*=\s*True\b`, _call_text(lines, i, m[0][1]))
}

_debug_on(lines, i, c, _) := "DebuggedApplication(evalex=True)" if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])DebuggedApplication\s*\((.*)$`, c, 1)
	count(m) > 0
	regex.match(`\bevalex\s*=\s*True\b`, _call_text(lines, i, m[0][1]))
}

_app_ref(name, "", apps) if name in apps

_app_ref(name, "()", _) if regex.match(`(?i)^(?:create|make|get|build)_?app$`, name)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*(?:from|import)\s+(?:flask|werkzeug)`, content)
	regex.match(`\b(?:debug|DEBUG|use_debugger|evalex)\s*=\s*True\b`, content)
	not helpers.is_test_path(path)
	apps := _apps(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:debug|DEBUG|use_debugger|evalex)\s*=|\.run\s*\(|\.config[.\[]|run_simple|DebuggedApplication`, line)
	not helpers.is_comment_line(line)
	what := _debug_on(lines, i, _code(line), apps)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Flask/Werkzeug debugger enabled (%s): its console executes Python for anyone who can reach an error page; drive debug from the environment and keep it off in deployment", [what]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

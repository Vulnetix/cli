# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1125

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1125",
	"name": "Excessive Attack Surface",
	"description": "A Python remote-procedure server configured to expose far more than the functions it was written to serve: an XML-RPC register_instance(obj, allow_dotted_names=True) (every attribute reachable through dotted names, including module globals, a documented remote-code path); RPyC serving SlaveService, ClassicService or MasterService, or the classic server, through ThreadedServer/ForkingServer/ThreadPoolServer/OneShotServer (the whole Python runtime is remote-callable); RPyC protocol_config allow_all_attrs, allow_setattr or allow_delattr set to True; Pyro4 REQUIRE_EXPOSE = False (every method of every registered object is remote-callable); and registering eval, exec, compile, __import__, open, os.system, os.popen or a subprocess function as an RPC function, directly or wrapped in a lambda (register_function(lambda cmd: os.popen(cmd).read(), \"shell\")). A call split over several lines is read as one. Not reported: register_instance without dotted names, a custom rpyc.Service subclass with exposed_ methods, Pyro objects with @expose, ordinary register_function of the application's own handlers, web routes (a route is the intended surface, not an excessive one), comments, strings and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1125/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1125],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["excessive-attack-surface", "cwe-1125", "rpc"],
}

_dangerous_fn := `(?:eval|exec|compile|__import__|open|os\.system|os\.popen|os\.exec\w*|subprocess\.\w+|builtins\.\w+)`

_patterns := [
	{
		"re": `\.register_instance\(.*\ballow_dotted_names\s*=\s*True\b`,
		"msg": "XML-RPC instance registered with allow_dotted_names=True: every attribute, including module globals, is remote-callable",
	},
	{
		"re": `\.register_instance\(\s*[\w.]+(?:\([^()]*\))?\s*,\s*True\s*\)`,
		"msg": "XML-RPC instance registered with allow_dotted_names=True: every attribute, including module globals, is remote-callable",
	},
	{
		"re": `\b(?:ThreadedServer|ForkingServer|ThreadPoolServer|OneShotServer)\(\s*(?:service\s*=\s*)?(?:[\w.]*\.)?(?:SlaveService|ClassicService|MasterService)\b`,
		"msg": "RPyC classic service served: the whole Python runtime of this process is remote-callable",
	},
	{
		"re": `["']allow_(?:all_attrs|setattr|delattr)["']\s*:\s*True\b|\ballow_(?:all_attrs|setattr|delattr)\s*=\s*True\b`,
		"msg": "RPyC protocol exposes every attribute (allow_all_attrs/allow_setattr/allow_delattr)",
	},
	{
		"re": `\bconfig\.REQUIRE_EXPOSE\s*=\s*False\b`,
		"msg": "Pyro REQUIRE_EXPOSE disabled: every method of every registered object is remote-callable",
	},
	{
		"re": concat("", [`\.register_function\(\s*`, _dangerous_fn, `\s*[,)]`]),
		"msg": "Code-execution or file primitive registered as a remote procedure",
	},
	{
		"re": concat("", [`\.register_function\(\s*lambda\b[^:]*:\s*(?:[\w.]+\()*?`, _dangerous_fn, `\(`]),
		"msg": "Code-execution or file primitive registered as a remote procedure",
	},
]

_gate := `register_instance|register_function|SlaveService|ClassicService|MasterService|allow_all_attrs|allow_setattr|allow_delattr|REQUIRE_EXPOSE`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(_gate, raw)
	not helpers.is_comment_line(raw)
	line := _logical(lines, i, raw)
	code := _unquoted_calls(line)
	some p in _patterns
	regex.match(p.re, code)
	finding := {
		"rule_id": metadata.id,
		"message": p.msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

# A quoted string that itself contains a call or assignment is prose (a log
# message, a docstring line); short keys such as "allow_all_attrs" are kept.
_unquoted_calls(line) := regex.replace(line, `"[^"]*[(=][^"]*"|'[^']*[(=][^']*'`, `""`)

# A call broken after its opening parenthesis (register_instance(\n obj,\n
# allow_dotted_names=True)) is read together with the next three lines.
_logical(_, _, raw) := raw if not regex.match(`\(\s*$`, raw)

_logical(lines, i, raw) := concat(" ", array.slice(lines, i, i + 4)) if regex.match(`\(\s*$`, raw)

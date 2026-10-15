# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1269

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1269",
	"name": "Product Released in Non-Release Configuration",
	"description": "A Python debugger hook is left in production code, so the shipped program stops at an interactive debugger prompt (hanging the worker, or handing a shell to whoever owns the terminal) or opens a remote-debug port that executes arbitrary code for anyone who connects. Reported, unconditionally reached (not inside an if that tests a debug, pdb, environment, settings, config, args or flag value): pdb/ipdb/pudb/rpdb/remote_pdb/web_pdb.set_trace(), pdb.post_mortem()/pm(), the built-in breakpoint(), a bare set_trace() or embed() imported from one of those debuggers or from IPython, __import__(\"pdb\").set_trace(), IPython.embed(), debugpy.listen()/wait_for_client()/breakpoint(), ptvsd.enable_attach()/wait_for_attach(), pydevd/pydevd_pycharm.settrace() and code.interact(). Not reported: a debugger behind a debug flag or environment check, a method or function of the program's own named set_trace or breakpoint (obj.set_trace(), self.breakpoint()), test files, an interactive console that is the program's own feature (code.interact() or embed() inside a function named for a shell, repl or console, as flask shell is), and the names in comments and strings. DEBUG = True framework settings are reported by VNX-215.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1269/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1269],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["product-released-in-non-release-config", "debugger", "python", "cwe-1269"],
}

_msg := "Debugger hook left in production code: the released program stops at an interactive debugger or opens a remote-debug port. Remove it, or gate it behind an explicit debug setting"

_code(line) := regex.replace(regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`), `#.*$`, "")

_debuggers := `(?:pdb|ipdb|pudb|rpdb|remote_pdb|web_pdb|pdbpp|wdb|celery\.contrib\.rdb|rdb)`

_call_res := [
	concat("", [`(?:^|[^\w.])`, _debuggers, `\s*\.\s*(?:set_trace|post_mortem|pm)\s*\(`]),
	`(?:^|[^\w.])breakpoint\s*\(\s*\)`,
	`(?:^|[^\w.])IPython\s*\.\s*embed\s*\(`,
	`(?:^|[^\w.])debugpy\s*\.\s*(?:listen|wait_for_client|breakpoint)\s*\(`,
	`(?:^|[^\w.])ptvsd\s*\.\s*(?:enable_attach|wait_for_attach|break_into_debugger)\s*\(`,
	`__import__\(DEBUGGER_MODULE\)\s*\.\s*set_trace\s*\(`,
	`(?:^|[^\w.])(?:\w+\s*\.\s*)?(?:Pdb|RemotePdb|Rpdb|Pudb)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\.\s*set_trace\s*\(`,
	`(?:^|[^\w.])pydevd(?:_pycharm)?\s*\.\s*settrace\s*\(`,
	`(?:^|[^\w.])code\s*\.\s*interact\s*\(`,
]

# set_trace()/embed() called bare after `from pdb import set_trace`, or under
# the alias of `from IPython import embed as shell`.
_bare_names(content) := {n |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*from\s+(?:`, _debuggers, `|IPython)\s+import\s+([\w ,]+)`]), content, -1)
	some part in split(m[1], ",")
	ws := regex.split(`\s+as\s+`, trim_space(part))
	trim_space(ws[0]) in {"set_trace", "post_mortem", "embed"}
	n := trim_space(ws[count(ws) - 1])
	n != ""
}

# `import pdb as debugger`: the alias is the debugger module.
_module_aliases(content) := {n |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*import\s+`, _debuggers, `\s+as\s+([A-Za-z_]\w*)`]), content, -1)
	n := m[1]
}

_is_call(c, _, _) if {
	some re in _call_res
	regex.match(re, c)
}

_is_call(c, bare, _) if {
	some n in bare
	regex.match(concat("", [`(?:^|[^\w.])`, n, `\s*\(`]), c)
	not regex.match(`^\s*def\s`, c)
}

_is_call(c, _, aliases) if {
	some n in aliases
	regex.match(concat("", [`(?:^|[^\w.])`, n, `\s*\.\s*(?:set_trace|post_mortem|pm)\s*\(`]), c)
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_flag_re := `(?i)(debug|pdb|trace|environ|getenv|env\b|settings|config|conf\b|args|opts|options|flag|verbose|interactive|isatty|post_mortem)`

# The nearest less-indented code line above i: its enclosing block header.
_parent(lines, i) := max(ks) if {
	ii := _indent(lines[i])
	ii > 0
	ks := [k |
		some k in numbers.range(max([0, i - 15]), i - 1)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
		_indent(lines[k]) < ii
	]
	count(ks) > 0
}

_flag_header(h) if {
	regex.match(`^\s*(if|elif|while)\b`, h)
	regex.match(_flag_re, h)
}

# A try/except/with/for block passes the question to its own enclosing block,
# so `if settings.DEBUG:` / `try:` / `import ipdb; ipdb.set_trace()` is gated.
_transparent(h) if regex.match(`^\s*(try|except|finally|with|for|async\s+with|async\s+for)\b`, h)

_gated(lines, i) if _flag_header(lines[_parent(lines, i)])

_gated(lines, i) if {
	p := _parent(lines, i)
	_transparent(lines[p])
	_flag_header(lines[_parent(lines, p)])
}

_gated(lines, i) if {
	p := _parent(lines, i)
	_transparent(lines[p])
	q := _parent(lines, p)
	_transparent(lines[q])
	_flag_header(lines[_parent(lines, q)])
}

# One-line form: `if args.pdb: pdb.set_trace()`.
_gated(lines, i) if {
	m := regex.find_all_string_submatch_n(`^\s*(?:if|elif)\b([^:]*):`, lines[i], 1)
	count(m) > 0
	regex.match(_flag_re, m[0][1])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`set_trace|settrace|breakpoint\s*\(|post_mortem|embed|debugpy|ptvsd|\.pm\s*\(|code\s*\.\s*interact\s*\(`, content)
	not helpers.is_test_path(path)
	not regex.match(`(^|/)conftest.py$`, path)
	bare := _bare_names(content)
	aliases := _module_aliases(content)
	names := bare | aliases
	lines := split(content, "\n")
	some i, line in lines
	_candidate(line, names)
	not helpers.is_comment_line(line)
	_is_call(_code_keep_import(line), bare, aliases)
	not _gated(lines, i)
	not _shell_command(lines, i)
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

# Literals are blanked, except the module name of __import__("pdb"), which is
# what makes that call a debugger.
_code_keep_import(line) := _code(regex.replace(line, `__import__\s*\(\s*["'](pdb|ipdb|pudb)["']\s*\)`, `__import__(DEBUGGER_MODULE)`))

# An interactive console that is the program's own feature (a `shell` or
# `repl` command, as `flask shell` is) is not a leftover debugger. Only the
# console calls are excused, never pdb or a remote-debug listener.
_shell_command(lines, i) if {
	regex.match(`(?:^|[^\w.])(?:code\s*\.\s*interact|(?:IPython\s*\.\s*)?embed)\s*\(`, lines[i])
	ii := _indent(lines[i])
	ks := [k |
		some k in numbers.range(max([0, i - 80]), i - 1)
		regex.match(`^\s*(?:async\s+)?def\s`, lines[k])
		_indent(lines[k]) < ii
	]
	count(ks) > 0
	regex.match(`(?i)^\s*(?:async\s+)?def\s+\w*(?:shell|repl|console|interact)`, lines[max(ks)])
}

_candidate(line, _) if regex.match(`set_trace|settrace|breakpoint|post_mortem|embed|debugpy|ptvsd|\.pm\s*\(|interact`, line)

_candidate(line, names) if {
	some n in names
	contains(line, n)
}

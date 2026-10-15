package vulnetix.rules.vnx_py_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-004",
	"name": "yaml.load() without SafeLoader",
	"description": "PyYAML is asked to construct arbitrary Python objects from a document: yaml.unsafe_load()/unsafe_load_all(), or yaml.load()/load_all() (through the module, an `import yaml as y` alias or a name imported with `from yaml import load`) whose Loader (keyword or second positional argument, read across a call broken over several lines) is Loader, UnsafeLoader, CLoader or CUnsafeLoader, or is missing (PyYAML before 5.1 then used the unsafe loader, and 5.1 to 5.4 defaulted to FullLoader, which had code-execution bypasses; 6.0 rejects the call). A !!python/object tag in such a document runs code. Not reported: yaml.safe_load()/safe_load_all(), SafeLoader, CSafeLoader, BaseLoader and CBaseLoader, FullLoader and full_load() (code-execution-free since PyYAML 5.4), a custom loader class whose safety cannot be read from its name, ruamel.yaml and other objects' .load() methods (YAML().load, self.yaml.load), and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-004/",
	"languages": ["python"],
	"severity": "high",
	"level": "warning",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["deserialization", "yaml", "dangerous-function"],
}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_fn_names := {"load", "load_all", "unsafe_load", "unsafe_load_all"}

# `import yaml as y`
_aliases(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+yaml\s+as\s+(\w+)`, content, -1)
}

# `from yaml import load, unsafe_load as ul` -> {"load": "load", "ul": "unsafe_load"}
_from_names(content) := {alias: ws[0] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+yaml\s+import\s+\(?([^\n)#]+)`, content, -1)
	some part in split(m[1], ",")
	ws := regex.split(`\s+as\s+`, trim_space(part))
	ws[0] in _fn_names
	alias := ws[count(ws) - 1]
}

# The module function (through the module, an alias or an imported name),
# not a method of another object (self.yaml.load).
_call_re(content) := re if {
	mods := concat("|", array.concat(["yaml"], [a | some a in _aliases(content)]))
	bare := [concat("", [`(`, a, `)`]) | some a, _ in _from_names(content)]
	alts := array.concat([concat("", [`(?:`, mods, `)\.(load_all|load|unsafe_load_all|unsafe_load)`])], bare)
	re := concat("", [`(?:^|[^\w.])(?:`, concat("|", alts), `)\s*\((.*)$`])
}

# The function a match names (the last group is the argument text).
_fn_of(m, names) := f if {
	some k in numbers.range(1, count(m) - 2)
	m[k] != ""
	f := _resolve(m[k], names)
}

_resolve(name, _) := name if name in _fn_names

_resolve(name, names) := names[name] if not name in _fn_names

_unsafe_loaders := {"Loader", "UnsafeLoader", "CLoader", "CUnsafeLoader"}

_depth(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

# The call's argument text: from the opening parenthesis to the line that
# balances it, at most six lines on.
_call_text(lines, i, rest) := rest if _depth(rest) < 0

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

_close_index(lines, i, rest) := k if {
	end := min([count(lines) - 1, i + 6])
	end >= i + 1
	d0 := _depth(rest) + 1
	ks := [j |
		some j in numbers.range(i + 1, end)
		d0 + sum([_depth(_code(lines[x])) | some x in numbers.range(i + 1, j)]) <= 0
	]
	count(ks) > 0
	k := ks[0]
}

_last(name) := parts[count(parts) - 1] if parts := split(name, ".")

# Keyword Loader=...
_loader(args) := _last(m[0][1]) if {
	m := regex.find_all_string_submatch_n(`\bLoader\s*=\s*([\w.]+)`, args, 1)
	count(m) > 0
}

# Second positional argument, when it is a plain (dotted) name.
_loader(args) := _last(m[0][1]) if {
	not regex.match(`\bLoader\s*=`, args)
	m := regex.find_all_string_submatch_n(`^\s*[^,()]*(?:\([^()]*\)[^,()]*)*,\s*([A-Za-z_][\w.]*)\s*(?:[,)]|$)`, args, 1)
	count(m) > 0
}

_unsafe(fn, _) if fn in {"unsafe_load", "unsafe_load_all"}

_unsafe(fn, args) if {
	fn in {"load", "load_all"}
	_loader(args) in _unsafe_loaders
}

_unsafe(fn, args) if {
	fn in {"load", "load_all"}
	not _loader(args)
	not regex.match(`\bLoader\s*=`, args)
}

_message(fn) := "yaml.unsafe_load() constructs arbitrary Python objects; use yaml.safe_load()" if fn in {"unsafe_load", "unsafe_load_all"}

_message(fn) := "yaml.load() without a safe Loader can construct arbitrary Python objects; use yaml.safe_load() or Loader=yaml.SafeLoader" if fn in {"load", "load_all"}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "yaml")
	contains(content, "load")
	re := _call_re(content)
	regex.match(concat("", ["(?m)", re]), content)
	names := _from_names(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "load")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(re, _code(line), 1)
	count(m) > 0
	fn := _fn_of(m[0], names)
	args := _call_text(lines, i, m[0][count(m[0]) - 1])
	_unsafe(fn, args)
	finding := {
		"rule_id": metadata.id,
		"message": _message(fn),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

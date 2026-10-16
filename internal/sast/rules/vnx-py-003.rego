package vulnetix.rules.vnx_py_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-003",
	"name": "Insecure deserialization with pickle",
	"description": "A pickle-format deserializer is called in a .py file: load(), loads() or Unpickler() of pickle, cPickle, _pickle, dill or cloudpickle, through the module, an `import pickle as x` alias (including a dotted path such as six.moves.cPickle) or a name imported with `from pickle import loads [as y]`, plus jsonpickle.decode() without safe=True. Unpickling runs whatever callable the data names (__reduce__), so any byte string that an attacker can influence (a cookie, an upload, a cache or queue entry) is code execution. Not reported: pickle.dump()/dumps() (serialising is safe), a round trip of data the same expression just serialised (pickle.loads(pickle.dumps(obj))), json/msgpack and other data-only formats, jsonpickle.decode(..., safe=True), methods of other objects named loads (serializer.loads), and the names in comments or string literals. Where the bytes come from is not judged: this rule is the one finding for a pickle call, including one fed from a request, a socket or a download (VNX-345 and VNX-PY-013 do not report it again); ML model loaders (torch.load, joblib.load, pandas.read_pickle) are VNX-PY-013.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-003/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059.006"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["deserialization", "dangerous-function"],
}

_mods := `(?:c?[Pp]ickle|_pickle|dill|cloudpickle)`

# String literal contents are blanked so a call named in a string is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# `import pickle as pkl`, `import six.moves.cPickle as pk`
_aliases(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*import\s+(?:[\w.]+\.)?`, _mods, `\s+as\s+(\w+)`]), content, -1)
}

# `from pickle import load, loads as unpickle`
_from_names(content) := {n |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*from\s+`, _mods, `\s+import\s+\(?([^\n)#]+)`]), content, -1)
	some part in split(m[1], ",")
	ws := regex.split(`\s+as\s+`, trim_space(part))
	ws[0] in {"load", "loads", "Unpickler"}
	n := ws[count(ws) - 1]
}

_sink_re(content) := re if {
	mods := concat("|", array.concat([_mods], [a | some a in _aliases(content)]))
	bare := [n | some n in _from_names(content)]
	alts := array.concat([concat("", [`(?:`, mods, `)\.(?:loads?|Unpickler)`]), `jsonpickle\.decode`], bare)
	re := concat("", [`(?:^|[^\w.])(`, concat("|", alts), `)\s*\((.*)$`])
}

# The bytes were serialised by the same expression: a deep-copy round trip.
_round_trip(arg) if regex.match(`^\s*[\w.]+\.dumps?\s*\(`, arg)

_arg(lines, i, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := _code(lines[j]) if {
	trim_space(rest) == ""
	j := helpers.next_code_index(lines, i, 3)
}

_arg(lines, i, rest) := "" if {
	trim_space(rest) == ""
	not helpers.next_code_index(lines, i, 3)
}

# jsonpickle.decode(s, safe=True) refuses to construct objects.
_safe_jsonpickle(fn, lines, i) if {
	fn == "jsonpickle.decode"
	regex.match(`safe\s*=\s*True`, helpers.code_window(lines, i, 0, 2))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`ickle|dill`, content)
	re := _sink_re(content)
	regex.match(concat("", ["(?m)", re]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\(`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(re, _code(line), 1)
	count(m) > 0
	fn := m[0][1]
	not _round_trip(_arg(lines, i, m[0][2]))
	not _safe_jsonpickle(fn, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() unpickles data, which can execute arbitrary code; use json or another data-only format for anything that crosses a trust boundary", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

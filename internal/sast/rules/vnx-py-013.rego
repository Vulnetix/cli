package vulnetix.rules.vnx_py_013

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-013",
	"name": "Python ML/AI insecure deserialization",
	"description": "A model, dataset or cached object is loaded with an ML or data loader that unpickles under the hood, which runs code embedded in the file: whoever can write or substitute the file (a downloaded checkpoint, a shared bucket, a user upload) gets code execution. Reported: joblib.load(), pandas.read_pickle(), numpy.load(..., allow_pickle=True), torch.load() without weights_only=True (or with weights_only=False), and Keras load_model(..., safe_mode=False), including module aliases (import pandas as pd), functions imported by name (from joblib import load as load_estimator) and arguments on continuation lines. Not reported: numpy.load without allow_pickle=True, torch.load(weights_only=True), torch.jit.load, safetensors, json, the dump/dumps writers, read_csv, load_model with the default safe mode, methods of other objects whose names merely contain pickle or load, and the pattern inside strings and comments. The pickle family itself (pickle, cPickle, _pickle, dill and cloudpickle load()/loads()/Unpickler()) is reported by VNX-PY-003, not here. Whether the file is trusted is not judged; torch.load is also reported by VNX-LLM-007.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-013/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["deserialization", "ml", "pytorch", "pickle", "supply-chain"],
}

_strip(line) := regex.replace(
	regex.replace(line, `"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'`, `""`),
	`#.*$`,
	"",
)

# The pickle family itself (pickle, cPickle, _pickle, dill, cloudpickle) is
# VNX-PY-003's: this rule owns the loaders that unpickle under the hood.
_kind := {
	"joblib": "joblib", "pandas": "pandas", "numpy": "numpy", "torch": "torch",
}

_defaults := {
	["joblib", "joblib"], ["pandas", "pandas"], ["pd", "pandas"],
	["numpy", "numpy"], ["np", "numpy"], ["torch", "torch"],
}

# [name, kind] for every import alias of a module this rule knows.
_aliases(content) := {[m[2], k] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+([\w\.]+)\s+as\s+(\w+)`, content, -1)
	base := regex.replace(m[1], `^.*\.`, "")
	k := _kind[base]
}

_bal(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

# The line plus continuation lines up to the closing parenthesis (at most 8).
_call_text(lines, i) := txt if {
	head := _strip(lines[i])
	_bal(head) <= 0
	txt := head
}

_call_text(lines, i) := txt if {
	head := _strip(lines[i])
	_bal(head) > 0
	last := min([count(lines) - 1, i + 8])
	ends := [j |
		some j in numbers.range(i + 1, last)
		_bal(concat("\n", [_strip(lines[k]) | some k in numbers.range(i, j)])) <= 0
	]
	end := min(array.concat([last], ends))
	txt := concat("\n", [_strip(lines[k]) | some k in numbers.range(i, end)])
}

_unsafe("joblib", "load", _) := true

_unsafe("pandas", "read_pickle", _) := true

_unsafe("numpy", "load", txt) if regex.match(`\ballow_pickle\s*=\s*True\b`, txt)

_unsafe("torch", "load", txt) if not regex.match(`\bweights_only\s*=\s*(?:True\b|[A-Za-z_][\w\.]*)`, txt)

_unsafe("torch", "load", txt) if regex.match(`\bweights_only\s*=\s*False\b`, txt)

_label("joblib") := "joblib.load()"

_label("pandas") := "pandas.read_pickle()"

_label("numpy") := "numpy.load(allow_pickle=True)"

_label("torch") := "torch.load() without weights_only=True"

_finding(path, i, line, what) := {
	"rule_id": metadata.id,
	"message": sprintf("Insecure deserialization: %s executes code embedded in the file it loads; load weights and data with a non-executable format (safetensors, ONNX, numpy without allow_pickle, torch.load(weights_only=True), JSON/Parquet) or verify the file's integrity first", [what]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`\.(?:loads?|Unpickler|read_pickle)\s*\(`, content)
	names := _defaults | _aliases(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:loads?|Unpickler|read_pickle)\s*\(`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w.])([A-Za-z_]\w*)\.(loads?|Unpickler|read_pickle)\s*\(`, code, -1)
	some pair in names
	pair[0] == m[1]
	txt := _call_text(lines, i)
	not _round_trip(txt)
	_unsafe(pair[1], m[2], txt)
	finding := _finding(path, i, line, _label(pair[1]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "safe_mode")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "load_model")
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[^\w])load_model\s*\(`, _strip(line))
	regex.match(`\bsafe_mode\s*=\s*False\b`, _call_text(lines, i))
	finding := _finding(path, i, line, "Keras load_model(safe_mode=False)")
}

# pickle.loads(pickle.dumps(x)) deep-copies an object this process created.
_round_trip(txt) if regex.match(`\.loads?\s*\(\s*[\w\.]*\.dumps?\s*\(`, txt)

# [local name, kind, method] for every deserializer imported by name:
# from joblib import load as load_estimator, from pandas import read_pickle.
_from_imports(content) := {[local, k, orig] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+(joblib|pandas|torch)\s+import\s+\(?([^\n#)]+)`, content, -1)
	k := _kind[m[1]]
	some part in split(m[2], ",")
	pm := regex.find_all_string_submatch_n(`^\s*(\w+)(?:\s+as\s+(\w+))?\s*$`, part, 1)
	count(pm) > 0
	orig := pm[0][1]
	orig in {"load", "loads", "Unpickler", "read_pickle"}
	local := _local_name(pm[0])
}

_local_name(pm) := pm[2] if pm[2] != ""

_local_name(pm) := pm[1] if pm[2] == ""

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*from\s+(?:joblib|pandas|torch)\s+import\s`, content)
	imported := _from_imports(content)
	count(imported) > 0
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:from|import)\s`, line)
	code := _strip(line)
	some entry in imported
	contains(code, entry[0])
	regex.match(concat("", [`(?:^|[^\w.])`, entry[0], `\s*\(`]), code)
	not regex.match(concat("", [`^\s*(?:async\s+)?def\s+`, entry[0], `\b`]), code)
	txt := _call_text(lines, i)
	not _round_trip(txt)
	_unsafe(entry[1], entry[2], txt)
	finding := _finding(path, i, line, _label(entry[1]))
}

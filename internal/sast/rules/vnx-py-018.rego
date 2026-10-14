package vulnetix.rules.vnx_py_018

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-018",
	"name": "Insecure temporary file creation via tempfile.mktemp()",
	"description": "A temporary file name is generated without creating the file, in a .py file: tempfile.mktemp() (also through `import tempfile as t` and `from tempfile import mktemp [as name]`), and the Python 2 os.tempnam()/os.tmpnam(). The name is free when it is returned, so another local user can create a file or symlink at that path before the program opens it (a TOCTOU race, CWE-377), and the program then writes into a file the attacker controls. Use tempfile.mkstemp(), NamedTemporaryFile(), TemporaryDirectory() or mkdtemp(), which create the file or directory atomically. Not reported: mkstemp/mkdtemp/NamedTemporaryFile/TemporaryFile, pytest's tmp_path_factory.mktemp() and other methods named mktemp (self.mktemp() in twisted.trial), a project function named mktemp, and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-018/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [377],
	"capec": ["CAPEC-29"],
	"attack_technique": ["T1574"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["tempfile", "race-condition", "toctou", "python"],
}

_code(line) := regex.replace(
	regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`),
	`#.*$`, "",
)

_modules(content) := {"tempfile"} | {m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+tempfile\s+as\s+(\w+)`, content, -1)
}

_from_names(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+tempfile\s+import\s+([^\n#]+)`, content, -1)
	some part in split(regex.replace(m[1], `[()\\]`, ""), ",")
	words := regex.split(`\s+`, trim_space(part))
	words[0] == "mktemp"
	n := words[count(words) - 1]
}

_patterns(content) := array.concat(
	array.concat(
		[concat("", [`(?:^|[^\w.])`, m, `\.mktemp\s*\(`]) | some m in _modules(content)],
		[concat("", [`(?:^|[^\w.])`, n, `\s*\(`]) | some n in _from_names(content)],
	),
	[`(?:^|[^\w.])os\.(?:tempnam|tmpnam)\s*\(`],
)

_message(code) := "os.tempnam()/os.tmpnam() return a name without creating the file (TOCTOU race); use tempfile.mkstemp() or NamedTemporaryFile()" if {
	regex.match(`os\.t(?:emp|mp)nam`, code)
}

_message(code) := "tempfile.mktemp() returns a name without creating the file (TOCTOU race); use tempfile.mkstemp(), NamedTemporaryFile() or mkdtemp()" if {
	not regex.match(`os\.t(?:emp|mp)nam`, code)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`mktemp|tempnam|tmpnam`, content)
	pats := _patterns(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`mktemp|tempnam|tmpnam|\(`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:async\s+)?def\s`, line)
	code := _code(line)
	some p in pats
	regex.match(p, code)
	finding := {
		"rule_id": metadata.id,
		"message": _message(code),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

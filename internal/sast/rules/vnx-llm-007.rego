package vulnetix.rules.vnx_llm_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-LLM-007",
	"name": "torch.load() without weights_only=True (ML model deserialization)",
	"description": "Reports a Python call to torch.load() (also through an `import torch as <alias>`) whose argument list, including arguments on continuation lines of a multi-line call, does not pass weights_only=True, or passes weights_only=False explicitly. torch.load() unpickles the file, so loading an untrusted or attacker-supplied checkpoint executes arbitrary code; weights_only=True restricts it to tensors and primitive containers, and the safetensors format avoids pickle altogether. Not reported: calls passing weights_only=True or a non-literal weights_only value, torch.jit.load() and safetensors loaders, lookalike receivers (mytorch.load, json.load), and the call written inside a string literal, docstring or comment.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-007/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["deserialization", "pytorch", "ml", "ai-security", "python"],
}

# String literals are blanked before matching so a docstring or a help text
# naming torch.load( is not a call.
_strip(line) := regex.replace(line, `"[^"]*"|'[^']*'`, `""`)

_aliases(content) := {a |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+torch\s+as\s+(\w+)`, content, -1)
	a := m[1]
}

_names(content) := {"torch"} | _aliases(content)

_bal(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

# The text of the call opened on line i: the rest of line i plus continuation
# lines up to the one that closes the parenthesis (at most 8 lines).
_call_text(lines, i, start) := txt if {
	head := substring(_strip(lines[i]), start, -1)
	_bal(head) <= 0
	txt := head
}

_call_text(lines, i, start) := txt if {
	head := substring(_strip(lines[i]), start, -1)
	_bal(head) > 0
	last := min([count(lines) - 1, i + 8])
	ends := [j |
		some j in numbers.range(i + 1, last)
		_bal(concat("\n", array.concat([head], [_strip(lines[k]) | some k in numbers.range(i + 1, j)]))) <= 0
	]
	end := min(array.concat([last], ends))
	txt := concat("\n", array.concat([head], [_strip(lines[k]) | some k in numbers.range(i + 1, end)]))
}

_safe(txt) if regex.match(`\bweights_only\s*=\s*(True|[A-Za-z_][\w\.]*)`, txt)

_unsafe(txt) if not _safe(txt)

_unsafe(txt) if regex.match(`\bweights_only\s*=\s*False\b`, txt)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, ".load(")
	regex.match(`(?m)^\s*(import\s+torch|from\s+torch\b)`, content)
	names := _names(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".load")
	not helpers.is_comment_line(line)
	code := _strip(line)
	some name in names
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w\.])(`, name, `\.load\s*\()`]), code, 1)
	count(m) > 0
	txt := _call_text(lines, i, indexof(code, m[0][1]))
	_unsafe(txt)
	finding := {
		"rule_id": metadata.id,
		"message": "torch.load() without weights_only=True unpickles the file and can execute arbitrary code from an untrusted checkpoint; pass weights_only=True or load safetensors",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

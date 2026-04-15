package vulnetix.rules.vnx_llm_006

import rego.v1

metadata := {
	"id": "VNX-LLM-006",
	"name": "LLM output interpolated into SQL query",
	"description": "Output from an LLM completion is interpolated directly into a SQL query string. Because LLM output can be manipulated via prompt injection, this creates a SQL injection vulnerability. Always use parameterized queries with bound parameters; never concatenate or f-string LLM output into SQL.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-006/",
	"languages": ["python"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["sql-injection", "llm", "ai-security", "prompt-injection"],
}

_is_py(path) if endswith(path, ".py")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "cursor.execute(")
	regex.match(`cursor\.execute\s*\(\s*f["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query constructed with f-string interpolation; if LLM output or user input is included, this is a SQL injection vulnerability — use parameterized queries with bound parameters",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`cursor\.execute\s*\(\s*["'][^"']*["']\s*\+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "SQL query constructed via string concatenation; if LLM output or user input is included, this is a SQL injection vulnerability — use parameterized queries with bound parameters",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_py(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.choices\[0\]\.message\.content`, line)
	not contains(line, "#")
	j := i + 1
	j < count(lines)
	next_line := lines[j]
	contains(next_line, "cursor.execute(")
	finding := {
		"rule_id": metadata.id,
		"message": "LLM completion output used directly before a cursor.execute() call; LLM output must not be interpolated into SQL — use parameterized queries",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_llm_002

import rego.v1

metadata := {
	"id": "VNX-LLM-002",
	"name": "LLM output passed to code execution (RCE)",
	"description": "LLM model output is passed directly to eval(), exec(), or a shell execution function. An attacker who influences the model response via prompt injection can execute arbitrary code on the server.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-002/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [95],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["llm", "code-injection", "rce", "ai-security"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(eval|exec)\s*\(\s*(response|content|result|output)`, line)
	regex.match(`(choices|message|content|llm|completion)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "LLM output passed to eval/exec; never execute model-generated content as code — validate and constrain tool call results",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`choices\[0\]\.message\.content`, line)
	regex.match(`(eval|exec|os\.system|subprocess)\s*\(`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "LLM response content passed to code or shell execution; this enables RCE if the model is manipulated via prompt injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

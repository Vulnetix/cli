package vulnetix.rules.vnx_llm_001

import rego.v1

metadata := {
	"id": "VNX-LLM-001",
	"name": "LLM prompt injection via user-controlled input",
	"description": "User-controlled input is directly interpolated into an LLM prompt string. An attacker can craft input that overrides the system prompt or instructs the model to perform unintended actions (prompt injection).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-001/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [77],
	"capec": ["CAPEC-137"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["llm", "prompt-injection", "ai-security"],
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
	regex.match(`(openai|anthropic|completion|chat).*f".*\{.*(request|user_input|user_message|query|prompt)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User-controlled input interpolated into LLM prompt; sanitize user input and use structured message construction to prevent prompt injection",
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
	regex.match(`(completions\.create|messages\.create|chat\.complete).*\+\s*(user_input|user_message|query|prompt|request)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User-controlled input concatenated into LLM prompt; use structured message construction to prevent prompt injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

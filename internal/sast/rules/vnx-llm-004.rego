package vulnetix.rules.vnx_llm_004

import rego.v1

metadata := {
	"id": "VNX-LLM-004",
	"name": "User input directly in LLM system prompt",
	"description": "User-controlled input is interpolated directly into the system prompt of an LLM API call (OpenAI, Anthropic, etc.). This enables prompt injection attacks where an attacker can override system instructions, leak the system prompt, or manipulate model behavior. Keep system prompts static and pass user input only in the user message role with appropriate guardrails.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-004/",
	"languages": ["python", "javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [77],
	"capec": ["CAPEC-137"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["prompt-injection", "llm", "ai-security", "system-prompt"],
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
	contains(line, `"role": "system"`)
	regex.match(`f["']|format\s*\(|\+\s*(user|request|input|query|prompt)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "User input appears to be interpolated into an LLM system prompt; keep system prompts static and place user content only in the 'user' role to prevent prompt injection",
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
	contains(line, "system=")
	regex.match(`system\s*=\s*f["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Anthropic system prompt constructed with an f-string; keep system prompts static and validate all user-supplied content before including it in prompts",
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
	regex.match(`PromptTemplate\.from_template\s*\(\s*f["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "LangChain PromptTemplate.from_template() called with an f-string; use template variables ({input}) instead of string interpolation to prevent prompt injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

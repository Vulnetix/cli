package vulnetix.rules.vnx_llm_001

import rego.v1
import data.vulnetix.helpers

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

# An LLM call spans several lines: the client call opens on one line and the
# message list with the interpolated prompt follows. Requiring the SDK name and
# the f-string on one line meant the canonical shape
#
#     response = client.chat.completions.create(
#         messages=[{"role": "system", "content": f"... {user_input}"}]
#
# was never flagged. _in_llm_call looks back over the open call instead.
_llm_call_re := `(openai|anthropic|bedrock|litellm|langchain|completions?\.create|messages\.create|chat\.complete|chat\.completions|generate_content|invoke_model|\.chat\()`

_in_llm_call(lines, i) if regex.match(_llm_call_re, lines[i])

# Both directions: the message list follows an open `create(`, but a prompt
# built into a local is assembled just above the call that consumes it.
_in_llm_call(lines, i) if {
	start := max([0, i - 10])
	end := min([count(lines) - 1, i + 6])
	some j in numbers.range(start, end)
	j != i
	not helpers.is_comment_line(lines[j])
	regex.match(_llm_call_re, lines[j])
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`f["'].*\{.*(request|user_input|user_message|user_query|query|prompt)`, line)
	_in_llm_call(lines, i)
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
	not helpers.is_comment_line(line)
	regex.match(`\+\s*(user_input|user_message|user_query|query|prompt|request)\b`, line)
	_in_llm_call(lines, i)
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

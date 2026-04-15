package vulnetix.rules.vnx_llm_003

import rego.v1

metadata := {
	"id": "VNX-LLM-003",
	"name": "Hardcoded LLM API key",
	"description": "An LLM provider API key (OpenAI sk-, Anthropic sk-ant-, Cohere, etc.) is hardcoded in source code. Hardcoded keys leak via version control and enable unauthorized model usage and cost abuse.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-llm-003/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "llm", "ai-security", "credentials"],
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
	regex.match(`sk-[a-zA-Z0-9]{20,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded OpenAI API key (sk-) found; rotate the key and load it from an environment variable or secrets manager",
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
	regex.match(`sk-ant-[a-zA-Z0-9\-_]{20,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded Anthropic API key (sk-ant-) found; rotate the key and load it from an environment variable or secrets manager",
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
	regex.match(`(api_key|apiKey|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*[=:]\s*["'][a-zA-Z0-9\-_]{20,}["']`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "LLM API key hardcoded in assignment; rotate the key and load it from an environment variable or secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

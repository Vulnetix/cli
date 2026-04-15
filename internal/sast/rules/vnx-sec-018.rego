package vulnetix.rules.vnx_sec_018

import rego.v1

metadata := {
	"id": "VNX-SEC-018",
	"name": "AI provider API key",
	"description": "An AI provider API key (Anthropic, OpenAI, or Hugging Face) was found in source code. These keys grant access to paid AI services and should be stored in environment variables or a secrets manager.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-018/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["secrets", "ai", "anthropic", "openai", "huggingface"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`sk-ant-[A-Za-z0-9\-_]{20,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Anthropic API key found; rotate the key and use environment variables or a secrets manager",
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
	regex.match(`sk-proj-[A-Za-z0-9]{20,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "OpenAI API key found; rotate the key and use environment variables or a secrets manager",
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
	regex.match(`hf_[A-Za-z0-9]{34,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hugging Face token found; rotate the token and use environment variables or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

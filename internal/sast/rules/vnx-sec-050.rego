package vulnetix.rules.vnx_sec_050

import rego.v1

metadata := {
	"id": "VNX-SEC-050",
	"name": "Google Gemini / Vertex AI / PaLM API key",
	"description": "A Google Gemini, Vertex AI, or PaLM API key (AIza prefix) was found in source code. These keys grant access to Google generative AI services and are commonly scraped from public repos.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-050/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secrets", "google", "gemini", "ai", "credentials"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`AIza[\w-]{35}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Google API key (Gemini/Vertex AI/PaLM) found; revoke the key in the Google Cloud console",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_sec_023

import rego.v1

metadata := {
	"id": "VNX-SEC-023",
	"name": "GitHub Actions expression injection via event data",
	"description": "A GitHub Actions workflow injects github.event data (PR title, branch name, comment body) directly into a run: command. An attacker can craft a PR title, branch name, or issue comment to inject arbitrary shell commands into the CI pipeline.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-023/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "open",
	"cwe": [77],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["ci-cd", "github-actions", "supply-chain", "command-injection"],
}

_is_workflow(path) if contains(path, ".github/workflows/")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_workflow(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\$\{\{\s*github\.event\.(pull_request\.(title|body|head\.ref)|issue\.body|comment\.body)\s*\}\}`, line)
	contains(line, "run:")
	finding := {
		"rule_id": metadata.id,
		"message": "GitHub Actions run: command injects untrusted github.event data; use an intermediate env var (env: TITLE: ${{ github.event.pull_request.title }}) to prevent shell injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_workflow(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\$\{\{\s*github\.head_ref\s*\}\}`, line)
	contains(line, "run:")
	finding := {
		"rule_id": metadata.id,
		"message": "GitHub Actions run: command injects github.head_ref; an attacker can create a branch with shell metacharacters — use an intermediate env var",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_sec_029

import rego.v1

metadata := {
	"id": "VNX-SEC-029",
	"name": "PyPI upload token hardcoded",
	"description": "A PyPI upload token (pypi-AgEIcHlwaS5vcmc prefix) appears hardcoded in source code. This token allows publishing packages to PyPI, enabling supply chain attacks if compromised. Revoke the token at pypi.org/manage/account/token and use trusted publishing or CI secrets instead.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-029/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["secret", "pypi", "registry", "supply-chain", "credentials"],
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
	regex.match(`pypi-AgEIcHlwaS5vcmc[0-9A-Za-z\-_]{50,}`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "PyPI upload token detected — revoke at pypi.org/manage/account/token and use Trusted Publishing or CI secrets instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

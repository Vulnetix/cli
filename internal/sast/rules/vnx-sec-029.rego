package vulnetix.rules.vnx_sec_029

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-029",
	"name": "PyPI upload token hardcoded",
	"description": "Reports a PyPI or TestPyPI API token: the macaroon prefix pypi-AgEIcHlwaS5vcmc (pypi.org) or pypi-AgENdGVzdC5weXBpLm9yZw (test.pypi.org) followed by at least 50 base64url characters, in any file (.pypirc, workflows, Makefiles, scripts). The bare prefix as a constant, placeholder and low-entropy bodies, ${{ secrets.* }} references, and test and fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-029/",
	"languages": ["generic"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secret", "pypi", "registry", "supply-chain", "credentials"],
}

_token_re := `(?:^|[^A-Za-z0-9_-])(pypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)([A-Za-z0-9_-]{50,}))`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	contains(content, "pypi-AgE")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "pypi-AgE")
	m := regex.find_all_string_submatch_n(_token_re, line, -1)
	some hit in m
	not secrets.is_example_token(hit[2])
	secrets.high_entropy(hit[2], 4.0)
	finding := {
		"rule_id": metadata.id,
		"message": "PyPI upload token detected; revoke at pypi.org/manage/account/token and use Trusted Publishing or CI secrets instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

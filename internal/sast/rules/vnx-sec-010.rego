package vulnetix.rules.vnx_sec_010

import rego.v1

import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-010",
	"name": "Package registry token",
	"description": "A package-registry publish credential is written into a file: an npm access token (npm_ followed by exactly 36 letters and digits) or a PyPI / TestPyPI API token (pypi-AgEIcHlwaS5vcmc... or pypi-AgENdGVzdC5weXBpLm9yZw... followed by its macaroon body) in any file, or a literal auth token in an .npmrc (_authToken= / _auth= / _password=) or .yarnrc.yml (npmAuthToken: / npmAuthIdent:, including under npmScopes), or a literal index password in .pypirc. A leaked publish token lets anyone release a malicious version of the package. Not reported: tokens read from the environment (${NPM_TOKEN}, $NPM_TOKEN), placeholder or low-entropy values, identifiers that merely begin with npm_ (npm_config_registry, npm_package_version), tokens embedded in a longer run of characters, lock files, minified bundles, and test, fixture and vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-010/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "npm", "pypi", "supply-chain", "credentials"],
}

_npm_re := `(?:^|[^A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?:[^A-Za-z0-9_]|$)`

_pypi_re := `(?:^|[^A-Za-z0-9_\-])(pypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)[A-Za-z0-9_\-]{50,})`

# An .npmrc / .yarnrc.yml credential line whose value is a literal, not an
# environment reference.
_rc_re := `^\s*(?:(?://[^\s=]*:)?_(?:authToken|auth|password)\s*=|npmAuth(?:Token|Ident)\s*:)\s*["']?([^\s"'$]{16,})["']?\s*$`

# A .pypirc index password that is a literal (a private index's deploy
# password, or a token), not an interpolation.
_pypirc_re := `^\s*password\s*[=:]\s*([^\s"'$%{]{8,})\s*$`

_message := {
	"npm": "npm access token found; revoke it with `npm token revoke` (or on npmjs.com), issue a new granular token and inject it from CI secrets",
	"pypi": "PyPI API token found; delete it under PyPI Account settings > API tokens, issue a new scoped token and use trusted publishing or CI secrets",
	"rc": "Registry auth token written into a package-manager config; replace it with ${NPM_TOKEN} and supply the token from the environment",
	"pypirc": "Package-index password written into .pypirc; remove it, rotate it, and pass it with TWINE_PASSWORD from CI secrets or use a keyring",
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".pypirc")
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(_pypirc_re, line, 1)
	count(m) > 0
	token := m[0][1]
	not startswith(token, "pypi-AgE") # reported as a PyPI token
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3)
	f := _finding(path, i, line, "pypirc")
}

_finding(path, i, line, kind) := {
	"rule_id": metadata.id,
	"message": _message[kind],
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": secrets.redact(line),
}

findings contains f if {
	some path, content in input.file_contents
	contains(content, "npm_")
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "npm_")
	some m in regex.find_all_string_submatch_n(_npm_re, line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	f := _finding(path, i, line, "npm")
}

findings contains f if {
	some path, content in input.file_contents
	contains(content, "pypi-AgE")
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "pypi-AgE")
	some m in regex.find_all_string_submatch_n(_pypi_re, line, -1)
	token := m[1]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 4)
	f := _finding(path, i, line, "pypi")
}

_rc_file(path) if endswith(path, ".npmrc")

_rc_file(path) if endswith(path, ".yarnrc.yml")

_rc_file(path) if endswith(path, ".yarnrc.yaml")

findings contains f if {
	some path, content in input.file_contents
	_rc_file(path)
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(_rc_re, line, 1)
	count(m) > 0
	token := m[0][1]
	not startswith(token, "npm_") # reported above
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3)
	f := _finding(path, i, line, "rc")
}

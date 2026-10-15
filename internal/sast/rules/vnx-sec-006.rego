package vulnetix.rules.vnx_sec_006

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-006",
	"name": "Stripe secret key",
	"description": "Reports a hard-coded Stripe secret API key in any file: a standalone sk_live_ (live mode) or sk_test_ (test mode) token of 24 or more alphanumeric characters, as assigned to stripe.api_key / Stripe.api_key / stripe.Key, passed to require('stripe')(…) or Stripe::setApiKey, or set in a .env file. Not reported: Stripe's published documentation test keys, placeholder runs (sk_live_xxxx…), publishable (pk_) and restricted (rk_, VNX-SEC-321/322) keys, prefix checks, environment references, and test, fixture, vendored and generated files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-006/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "stripe", "payment", "credentials"],
}

_token := `(?:^|[^A-Za-z0-9_])(sk_(live|test)_[0-9a-zA-Z]{24,247})(?:[^A-Za-z0-9_]|$)`

# Keys Stripe prints in its public API reference; they belong to Stripe's
# demo account and appear in countless tutorials.
_docs_keys := {
	concat("", ["sk_test_", "4eC39HqLyjWDarjtT1zdp7dc"]),
	concat("", ["sk_test_", "BQokikJOvBiI2HlWgH4olfQ2"]),
	concat("", ["sk_test_", "26PHem9AhJZvU623DfE1x4sd"]),
}

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "sk_")
	regex.match(`sk_(?:live|test)_[0-9a-zA-Z]{24}`, content)
	not secrets.skip_path(path)
	not _test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`sk_(?:live|test)_`, line)
	some m in regex.find_all_string_submatch_n(_token, line, -1)
	token := m[1]
	not _docs_keys[token]
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3.5)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Stripe %s-mode secret key found; roll it in the Stripe Dashboard (Developers > API keys) and load it from the environment or a secrets manager", [m[2]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

# Test code beyond helpers.is_test_path: Jest __mocks__ directories and Xcode
# test targets (AppTests/, FooTests.swift), which hold fake credentials.
_test_path(path) if helpers.is_test_path(path)

_test_path(path) if regex.match(`(^|/)(__mocks__|[A-Za-z0-9_]*Tests)/|Tests?\.swift$`, path)

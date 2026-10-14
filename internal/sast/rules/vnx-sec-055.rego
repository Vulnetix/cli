package vulnetix.rules.vnx_sec_055

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-055",
	"name": "New Relic API key",
	"description": "Reports a New Relic credential as a whole token in any file: a user API key (NRAK- and 27 characters), an insert key (NRII- and 27 to 32 characters), an ingest license key (36 characters ending in NRAL), or a browser key (NRJS- and 19 hex characters) held in configuration. User keys query and change account data through NerdGraph; insert and license keys write telemetry. Not reported: the browser key inside the NREUM loader snippet (licenseKey in loader_config is public by design), prefixes on their own, placeholder bodies, template or environment references, and test, fixture or vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-055/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "newrelic", "monitoring", "credentials"],
}

_tokens := [
	{
		"marker": "NRAK-",
		"re": `(?:^|[^A-Za-z0-9_-])NRAK-([A-Za-z0-9]{27})(?:[^A-Za-z0-9_-]|$)`,
		"msg": "New Relic user API key found; delete it in New Relic (API keys) and load the replacement from a secret store",
	},
	{
		"marker": "NRII-",
		"re": `(?:^|[^A-Za-z0-9_-])NRII-([A-Za-z0-9_-]{27,32})(?:[^A-Za-z0-9_-]|$)`,
		"msg": "New Relic insert key found; delete it in New Relic (API keys) and load the replacement from a secret store",
	},
	{
		"marker": "NRAL",
		"re": `(?:^|[^A-Za-z0-9_-])([A-Za-z0-9]{36})NRAL(?:[^A-Za-z0-9_-]|$)`,
		"msg": "New Relic ingest license key found; rotate it in New Relic (API keys) and set it through NEW_RELIC_LICENSE_KEY from a secret store",
	},
	{
		"marker": "NRJS-",
		"re": `(?:^|[^A-Za-z0-9_-])NRJS-([a-f0-9]{19})(?:[^A-Za-z0-9_-]|$)`,
		"msg": "New Relic browser key found outside the browser agent snippet; rotate it in New Relic (API keys) if it is used server-side",
	},
]

# The browser agent loader embeds the NRJS key in every page on purpose.
_public_loader(line) if regex.match(`NREUM|loader_config|licenseKey`, line)

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	some t in _tokens
	contains(content, t.marker)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, t.marker)
	m := regex.find_all_string_submatch_n(t.re, line, 1)
	count(m) > 0
	body := m[0][1]
	not secrets.is_example_token(body)
	not _loader_key(t.marker, line)
	finding := {
		"rule_id": metadata.id,
		"message": t.msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

_loader_key("NRJS-", line) if _public_loader(line)

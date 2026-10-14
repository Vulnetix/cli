package vulnetix.rules.vnx_sec_054

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-054",
	"name": "Datadog API / APP key",
	"description": "Reports a hard-coded Datadog API key (32 lower-case hex characters) or application key (40 hex characters) assigned to a Datadog key name (DD_API_KEY, DD_APP_KEY, datadog_api_key, DATADOG_APPLICATION_KEY), or to a generic api_key/app_key/apiKey/appKey/apiKeyAuth/appKeyAuth when the file is Datadog configuration (a path naming datadog) or a line naming Datadog appears within eight lines above (provider \"datadog\", from datadog import, @datadog/datadog-api-client, a datadog: block). The keys read and write metrics, logs, monitors and dashboards. Not reported: hex values with no Datadog context (commit hashes, other providers' keys), the public RUM client token (pub...), variable or environment references, placeholder bodies, and test, fixture or vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-054/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "datadog", "monitoring", "credentials"],
}

_value := `\s*["']?\s*[:=]\s*["']?([a-f0-9]{40}|[a-f0-9]{32})(?:[^A-Za-z0-9]|$)`

# A key name that is itself Datadog's.
_named := concat("", [`(?i)\b(?:dd|datadog)[_-]?(?:api|app|application)[_-]?key`, _value])

# A generic key name, reported only with Datadog context.
_generic := concat("", [`(?i)(?:^|[^A-Za-z0-9])(?:api[_-]?key|app[_-]?key|application[_-]?key|api[_-]?key[_-]?auth|app[_-]?key[_-]?auth)`, _value])

_hit(line, _, _, _) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_named, line, 1)
	count(m) > 0
}

_hit(line, path, lines, i) := m[0][1] if {
	m := regex.find_all_string_submatch_n(_generic, line, 1)
	count(m) > 0
	_context(path, lines, i)
}

_context(path, _, _) if contains(lower(path), "datadog")

_context(_, lines, i) if {
	window := concat("\n", array.slice(lines, max([0, i - 8]), i + 1))
	contains(lower(window), "datadog")
}

_dd_file(path, _) if contains(lower(path), "datadog")

_dd_file(_, content) if contains(content, "atadog")

_dd_file(_, content) if contains(content, "ATADOG")

_dd_file(_, content) if {
	some p in ["DD_A", "dd_a", "DD-A", "dd-a"]
	contains(content, p)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	_dd_file(path, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`[Kk][Ee][Yy][^a-f0-9]{0,10}[a-f0-9]{32}`, line)
	token := _hit(line, path, lines, i)
	not secrets.is_example_token(token)
	secrets.high_entropy(token, 3)
	finding := {
		"rule_id": metadata.id,
		"message": "Datadog API or application key found; revoke it in Datadog (Organization Settings > API Keys / Application Keys) and inject the replacement from a secret store",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

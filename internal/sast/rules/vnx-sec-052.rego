package vulnetix.rules.vnx_sec_052

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-052",
	"name": "Artifactory / JFrog API key",
	"description": "Reports a JFrog Artifactory credential as a whole token in any file: a legacy API key (AKCp followed by 69 letters and digits, 73 characters) or a reference/access token (cmVmd followed by 59 letters and digits, 64 characters), for example in .npmrc, gradle.properties, an X-JFrog-Art-Api header or a Bearer header. Either grants the owner's access to the Artifactory repositories, so artifacts can be read or replaced. Not reported: the prefix inside a longer alphanumeric run (base64 data), shorter lookalikes such as base64 of 'refund', placeholder bodies, environment references, and test, fixture or vendored paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-052/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "artifactory", "jfrog", "supply-chain", "credentials"],
}

_tokens := [
	{
		"prefix": "AKCp",
		"re": `(?:^|[^A-Za-z0-9])(AKCp[A-Za-z0-9]{69})(?:[^A-Za-z0-9]|$)`,
		"msg": "Artifactory API key found; revoke it in the JFrog platform (Edit Profile > API Key) and switch to a scoped access token held in a secret store",
	},
	{
		"prefix": "cmVmd",
		"re": `(?:^|[^A-Za-z0-9])(cmVmd[A-Za-z0-9]{59})(?:[^A-Za-z0-9]|$)`,
		"msg": "JFrog reference token found; revoke it in the JFrog platform (Identity and Access > Access Tokens) and load the replacement from a secret store",
	},
]

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	some t in _tokens
	contains(content, t.prefix)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, t.prefix)
	m := regex.find_all_string_submatch_n(t.re, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(substring(token, count(t.prefix), -1))
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

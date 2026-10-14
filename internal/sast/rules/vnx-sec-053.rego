package vulnetix.rules.vnx_sec_053

import rego.v1
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-053",
	"name": "SonarQube / SonarCloud token",
	"description": "Reports a SonarQube or SonarCloud token as a whole token in any file: a user token (squ_), project analysis token (sqp_) or global analysis token (sqa_) followed by exactly 40 lower-case hex characters, for example sonar.token in sonar-project.properties, SONAR_TOKEN in a workflow or -Dsonar.login on a Maven command line. The token can read source and findings and submit analyses. Not reported: identifiers that merely start with squ_/sqp_/sqa_, placeholder bodies, CI secret references, and test, fixture or vendored paths. Snyk tokens are UUIDs or snyk_-prefixed and are reported by VNX-SEC-1020 and VNX-SEC-1021, not here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-053/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "sonarqube", "credentials"],
}

_pattern := `(?:^|[^A-Za-z0-9_])((?:squ|sqp|sqa)_[a-f0-9]{40})(?:[^A-Za-z0-9_]|$)`

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	regex.match(`sq[upa]_[a-f0-9]{40}`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "_")
	m := regex.find_all_string_submatch_n(_pattern, line, 1)
	count(m) > 0
	token := m[0][1]
	not secrets.is_example_token(substring(token, 4, -1))
	secrets.high_entropy(substring(token, 4, -1), 3)
	finding := {
		"rule_id": metadata.id,
		"message": "SonarQube token found; revoke it in SonarQube (My Account > Security) and pass the replacement through a CI secret",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}

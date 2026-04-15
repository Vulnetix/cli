package vulnetix.rules.vnx_java_010

import rego.v1

metadata := {
	"id": "VNX-JAVA-010",
	"name": "Spring CSRF protection disabled",
	"description": "Disabling CSRF protection in Spring Security allows cross-site request forgery attacks where malicious websites can perform actions on behalf of authenticated users.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-010/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [352],
	"capec": ["CAPEC-62"],
	"attack_technique": ["T1189"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["csrf", "spring", "web-security"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_csrf_disable_indicators := {
	"csrf().disable()",
	"csrf(csrf -> csrf.disable())",
	"csrf(AbstractHttpConfigurer::disable)",
	".csrf().ignoringAntMatchers",
	"csrf.disable()",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _csrf_disable_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "CSRF protection disabled in Spring Security; enable CSRF protection for state-changing endpoints",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

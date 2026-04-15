package vulnetix.rules.vnx_java_002

import rego.v1

metadata := {
	"id": "VNX-JAVA-002",
	"name": "Spring actuator endpoints exposed",
	"description": "Exposing all Spring Boot actuator endpoints (e.g. management.endpoints.web.exposure.include=*) can leak heap dumps, environment variables, and enable remote shutdown.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-JAVA-002",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [200],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["spring", "config", "actuator", "information-disclosure"],
}

_is_app_props(path) if endswith(path, "application.properties")
_is_app_props(path) if endswith(path, "application.yml")
_is_app_props(path) if endswith(path, "application.yaml")
_is_app_props(path) if endswith(path, "application-prod.properties")
_is_app_props(path) if endswith(path, "application-prod.yml")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_app_props(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "management.endpoints.web.exposure.include")
	regex.match(`.*=\s*\*`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "All actuator endpoints exposed; restrict to health,info or use Spring Security",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

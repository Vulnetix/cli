package vulnetix.rules.vnx_docker_003

import rego.v1

metadata := {
	"id": "VNX-DOCKER-003",
	"name": "Secret in Dockerfile ARG or ENV",
	"description": "ARG or ENV instructions with names suggesting credentials (PASSWORD, SECRET, TOKEN, KEY, CREDENTIAL) bake secrets into image layers and history, where they can be extracted.",
	"help_uri": "https://docs.vulnetix.com/rules/VNX-DOCKER-003",
	"languages": ["docker"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "secrets", "credentials", "container"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, "Dockerfile")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`^\s*(ARG|ENV)\s+\w*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY)\w*\s*=`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Secret value in Dockerfile ARG/ENV is baked into image layers; use --secret mount or runtime environment variables instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_docker_008

import rego.v1

metadata := {
	"id": "VNX-DOCKER-008",
	"name": "Dockerfile package manager install without version pinning",
	"description": "apt-get install, apk add, or yum install is used without pinning package versions. Unpinned package installs allow builds to silently pull newer, potentially vulnerable or breaking versions, making builds non-reproducible and introducing supply chain risk. Pin versions with apt-get install pkg=1.2.3-4 or apk add pkg=1.2.3.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-008/",
	"languages": ["docker"],
	"severity": "low",
	"level": "warning",
	"kind": "open",
	"cwe": [1357],
	"capec": ["CAPEC-538"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "supply-chain", "reproducibility", "container"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, "Dockerfile")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`apt-get install\s`, line)
	not regex.match(`apt-get install\s[^\\n]*=`, line)
	not regex.match(`^\s*#`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "apt-get install without version pinning: pin packages with pkg=version to ensure reproducible builds and prevent supply chain drift",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, "Dockerfile")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`apk add\s`, line)
	not regex.match(`apk add\s[^\\n]*=`, line)
	not regex.match(`apk add\s--no-cache\s[^\\n]*=`, line)
	not regex.match(`^\s*#`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "apk add without version pinning: pin packages with pkg=version to ensure reproducible builds and prevent supply chain drift",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

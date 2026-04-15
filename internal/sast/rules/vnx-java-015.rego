package vulnetix.rules.vnx_java_015

import rego.v1

metadata := {
	"id": "VNX-JAVA-015",
	"name": "Java JPQL/HQL injection via string concatenation",
	"description": "Untrusted input is concatenated into a JPQL, HQL, or native SQL query string passed to EntityManager.createQuery() or Session.createQuery(). This enables query injection that can expose, modify, or delete data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-015/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [89],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["sql-injection", "jpql", "jpa", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(createQuery|createNativeQuery|createNamedQuery)\s*\(.*\+`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "JPQL/HQL query constructed with string concatenation; use named parameters (:param) or positional parameters (?1) with setParameter() to prevent injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`(createQuery|createNativeQuery)\s*\(.*String\.format`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "JPQL/HQL query constructed with String.format; use named parameters (:param) with setParameter() to prevent injection",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

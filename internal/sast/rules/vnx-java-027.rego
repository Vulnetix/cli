package vulnetix.rules.vnx_java_027

import rego.v1

metadata := {
	"id": "VNX-JAVA-027",
	"name": "Java Spring security headers disabled or absent (clickjacking, CSP)",
	"description": "Spring Security's headers() configuration explicitly disables X-Frame-Options, Content-Security-Policy, or HSTS, or the frameOptions().disable() / headers().disable() call is present. Without these headers the application is vulnerable to clickjacking and other UI-redressing attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-027/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [693],
	"capec": ["CAPEC-103"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:M/IC:M/FC:M/RP:M/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["security-headers", "clickjacking", "spring", "java"],
}

_is_java(path) if endswith(path, ".java")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "frameOptions()")
	contains(line, ".disable()")
	finding := {
		"rule_id": metadata.id,
		"message": "Spring Security X-Frame-Options explicitly disabled; configure frameOptions().deny() or frameOptions().sameOrigin() to prevent clickjacking",
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
	regex.match(`\.headers\(\s*\)\s*\.disable\(\)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Spring Security HTTP security headers entirely disabled; re-enable headers() and configure X-Frame-Options, CSP, and HSTS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

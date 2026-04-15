package vulnetix.rules.vnx_php_020

import rego.v1

metadata := {
	"id": "VNX-PHP-020",
	"name": "PHP curl SSL certificate verification disabled",
	"description": "CURLOPT_SSL_VERIFYPEER is set to false or 0, disabling TLS certificate validation for curl requests. This allows man-in-the-middle attackers to intercept or modify HTTPS traffic without detection. Remove the option or set it to true; if using self-signed certs in development, use CURLOPT_CAINFO to specify the CA bundle.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-020/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["tls", "ssl", "curl", "mitm", "php"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "CURLOPT_SSL_VERIFYPEER")
	regex.match(`CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0|FALSE)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "CURLOPT_SSL_VERIFYPEER disabled; TLS certificate validation is off, enabling MITM attacks — remove this option or set it to true",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "CURLOPT_SSL_VERIFYHOST")
	regex.match(`CURLOPT_SSL_VERIFYHOST\s*,\s*(false|0|FALSE)`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "CURLOPT_SSL_VERIFYHOST disabled; TLS hostname validation is off, enabling MITM attacks — set to 2 (the default) to enforce hostname matching",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

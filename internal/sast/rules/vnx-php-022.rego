package vulnetix.rules.vnx_php_022

import rego.v1

metadata := {
	"id": "VNX-PHP-022",
	"name": "PHP open redirect via non-literal redirect destination",
	"description": "header('Location: ...') or a framework redirect function is called with a user-controlled or non-literal URL. An attacker can craft a link that redirects victims to a malicious site, enabling phishing. Validate the redirect target against an allowlist of known safe internal paths, or use only relative paths for redirects.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-022/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1598"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:H/IC:M/FC:M/RP:M/RL:M/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["open-redirect", "redirect", "symfony", "laravel", "php"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "this->redirect(")
	not regex.match(`this->redirect\s*\(\s*['"]`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "$this->redirect() called with a non-literal URL; validate the destination against an allowlist to prevent open redirect attacks",
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
	regex.match(`header\s*\(\s*['"]Location:\s*['"]`, line)
	regex.match(`\$_(GET|POST|REQUEST|COOKIE)\[`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "header('Location:') with user-controlled value enables open redirect; validate the URL against an allowlist of safe destinations",
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
	contains(line, "Redirect::to(")
	not regex.match(`Redirect::to\s*\(\s*['"]`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Laravel Redirect::to() called with non-literal URL; validate the destination against an allowlist to prevent open redirect attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

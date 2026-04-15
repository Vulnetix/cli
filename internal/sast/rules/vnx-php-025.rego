package vulnetix.rules.vnx_php_025

import rego.v1

metadata := {
	"id": "VNX-PHP-025",
	"name": "PHP deprecated mcrypt encryption functions",
	"description": "mcrypt_encrypt(), mcrypt_decrypt(), or other mcrypt_ functions are used. The mcrypt extension was deprecated in PHP 7.1 and removed in PHP 7.2 due to its use of outdated and insecure cipher implementations (e.g. DES, 3DES) and its unmaintained codebase. Migrate to the OpenSSL extension (openssl_encrypt/decrypt with AES-256-GCM) or the Sodium extension.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-025/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-20"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["weak-crypto", "mcrypt", "deprecated", "php"],
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`mcrypt_(encrypt|decrypt|cbc|cfb|ecb|ofb|create_iv|generic|get_|list_|module_|open|rand)\s*\(`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Deprecated mcrypt function detected; mcrypt was removed in PHP 7.2 — migrate to openssl_encrypt/decrypt with AES-256-GCM or the Sodium extension",
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
	regex.match(`mdecrypt_(generic)\s*\(`, line)
	not contains(line, "//")
	finding := {
		"rule_id": metadata.id,
		"message": "Deprecated mdecrypt function detected; mcrypt was removed in PHP 7.2 — migrate to openssl_encrypt/decrypt with AES-256-GCM or the Sodium extension",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

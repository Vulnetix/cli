package vulnetix.rules.vnx_android_004

import rego.v1

metadata := {
	"id": "VNX-ANDROID-004",
	"name": "Android SharedPreferences used for sensitive data storage",
	"description": "SharedPreferences stores data as a plaintext XML file on the device. Storing passwords, tokens, or other sensitive values in SharedPreferences (even with MODE_PRIVATE) exposes them to root-enabled devices, device backups, and memory-forensics.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-004/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [312],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1409"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["android", "shared-preferences", "insecure-storage", "mobile-security"],
}

_is_java(path) if endswith(path, ".java")
_is_java(path) if endswith(path, ".kt")

_sensitive_terms := {
	"password",
	"Password",
	"passwd",
	"token",
	"Token",
	"secret",
	"Secret",
	"apiKey",
	"api_key",
	"privateKey",
	"private_key",
	"authToken",
	"auth_token",
	"accessToken",
	"access_token",
	"sessionId",
	"session_id",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_java(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "putString")
	window_start := max([0, i - 10])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	contains(window, "SharedPreferences")
	some term in _sensitive_terms
	contains(line, term)
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive data stored in SharedPreferences; use the Android Keystore system or EncryptedSharedPreferences from the Jetpack Security library to store credentials securely",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

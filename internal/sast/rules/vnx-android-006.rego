package vulnetix.rules.vnx_android_006

import rego.v1

metadata := {
	"id": "VNX-ANDROID-006",
	"name": "Android hardcoded API key in strings.xml",
	"description": "A string resource whose name suggests it is a credential (api_key, secret, token, password) contains a value in strings.xml. Hardcoded credentials in resource files can be extracted from the APK by anyone who decompiles it.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-006/",
	"languages": ["android"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["android", "hardcoded-credentials", "secrets", "mobile-security"],
}

_is_strings_xml(path) if endswith(path, "strings.xml")
_is_strings_xml(path) if {
	endswith(path, ".xml")
	contains(path, "res/values")
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_strings_xml(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`<string\s+name\s*=\s*"[^"]*(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|auth)[^"]*"`, line)
	# Only flag when the string has a non-empty value
	regex.match(`>[^<]{4,}<`, line)
	not contains(line, "PLACEHOLDER")
	not contains(line, "YOUR_")
	not contains(line, "REPLACE")
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded credential found in Android string resource; move secrets to a secure server-side config, Android Keystore, or use runtime injection via BuildConfig variables from CI secrets",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

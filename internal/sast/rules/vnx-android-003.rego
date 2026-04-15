package vulnetix.rules.vnx_android_003

import rego.v1

metadata := {
	"id": "VNX-ANDROID-003",
	"name": "Android exported component without permission check",
	"description": "An Activity, Service, BroadcastReceiver, or ContentProvider is exported in the AndroidManifest without requiring a permission. Any third-party application on the device can invoke this component, potentially accessing sensitive functionality or data.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-003/",
	"languages": ["android"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [926],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1427"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["android", "manifest", "exported-component", "mobile-security"],
}

_is_manifest(path) if contains(path, "AndroidManifest.xml")
_is_manifest(path) if endswith(path, ".xml")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_manifest(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Component with android:exported="true" but no permission on same line
	regex.match(`android:exported\s*=\s*"true"`, line)
	not regex.match(`android:permission\s*=`, line)
	# Confirm it's a component declaration
	regex.match(`<(activity|service|receiver|provider)(\s|>)`, line)
	# Check the next few lines for a permission attr
	window_end := min([count(lines) - 1, i + 8])
	window_lines := array.slice(lines, i, window_end + 1)
	window := concat("\n", window_lines)
	not contains(window, "android:permission")
	finding := {
		"rule_id": metadata.id,
		"message": "Android component exported without android:permission; add android:permission with a signature-level or custom permission to restrict access to authorised callers only",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

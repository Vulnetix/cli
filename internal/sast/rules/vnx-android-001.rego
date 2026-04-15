package vulnetix.rules.vnx_android_001

import rego.v1

metadata := {
	"id": "VNX-ANDROID-001",
	"name": "Android insecure manifest configuration",
	"description": "Setting android:debuggable='true' or android:allowBackup='true' in AndroidManifest.xml exposes the app to debugging attacks and data extraction.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-001/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [489, 921],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1409"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["android", "manifest", "mobile-security"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_manifest_indicators := {
	"android:debuggable=\"true\"",
	"android:allowBackup=\"true\"",
	"android:usesCleartextTraffic=\"true\"",
	"android:exported=\"true\"",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _manifest_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Insecure Android manifest setting: %s; disable for production builds", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

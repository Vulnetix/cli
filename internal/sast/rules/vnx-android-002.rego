package vulnetix.rules.vnx_android_002

import rego.v1

metadata := {
	"id": "VNX-ANDROID-002",
	"name": "Android WebView JavaScript enabled",
	"description": "Enabling JavaScript in WebView (setJavaScriptEnabled(true)) and adding JavaScript interfaces (addJavascriptInterface) can expose the app to XSS and remote code execution.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-002/",
	"languages": ["java"],
	"severity": "high",
	"level": "warning",
	"kind": "open",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["android", "webview", "xss", "mobile-security"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_webview_indicators := {
	"setJavaScriptEnabled(true)",
	"addJavascriptInterface(",
	"setAllowFileAccess(true)",
	"setAllowUniversalAccessFromFileURLs(true)",
	"setAllowFileAccessFromFileURLs(true)",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _webview_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Insecure WebView setting: %s; restrict JavaScript and file access in WebView", [indicator]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_swift_005

import rego.v1

metadata := {
	"id": "VNX-SWIFT-005",
	"name": "Swift WKWebView JavaScript auto-open-windows enabled",
	"description": "WKPreferences.javaScriptCanOpenWindowsAutomatically is set to true, allowing JavaScript running inside the WebView to open new windows without user interaction. Combined with user-supplied content this can enable XSS escalation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-005/",
	"languages": ["swift"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [272],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["webview", "xss", "swift", "ios"],
}

_is_swift(path) if endswith(path, ".swift")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "javaScriptCanOpenWindowsAutomatically")
	contains(line, "true")
	finding := {
		"rule_id": metadata.id,
		"message": "WKPreferences.javaScriptCanOpenWindowsAutomatically set to true; disable this setting unless your application explicitly requires JavaScript to open new windows",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Deprecated UIWebView JavaScript enabled
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`UIWebView|webView.*javascriptEnabled|allowsInlineMediaPlayback`, line)
	contains(line, "UIWebView")
	finding := {
		"rule_id": metadata.id,
		"message": "UIWebView is deprecated and has unmitigated JavaScript security risks; migrate to WKWebView with a strict content security policy",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

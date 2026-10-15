package vulnetix.rules.vnx_swift_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SWIFT-005",
	"name": "Swift WKWebView JavaScript auto-open-windows enabled, or deprecated UIWebView in use",
	"description": "Reports a Swift assignment of true to WKPreferences.javaScriptCanOpenWindowsAutomatically (directly or through configuration.preferences), which lets script in the web view open windows without a user gesture, and the first use of the deprecated UIWebView type in a file (a property, outlet, parameter, cast or UIWebView(...) instance), since UIWebView always runs JavaScript, cannot disable it or isolate content and is rejected by App Store review. Not reported: the setting assigned false or only read, WKWebView, UIWebViewDelegate or UIWebView.NavigationType without a UIWebView reference of its own, the names inside string literals (NSClassFromString(\"UIWebView\")) and identifiers that merely contain the word, comment lines and test files. Further UIWebView references in the same file are not reported again.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-005/",
	"languages": ["swift"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [272],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["webview", "xss", "swift", "ios"],
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)[^/]*Tests?/`, path)

_is_test(path) if regex.match(`Tests?\.swift$`, path)

_strip(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	contains(content, "javaScriptCanOpenWindowsAutomatically")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "javaScriptCanOpenWindowsAutomatically")
	not helpers.is_comment_line(line)
	regex.match(`\.javaScriptCanOpenWindowsAutomatically\s*=\s*true\b`, _strip(line))
	finding := {
		"rule_id": metadata.id,
		"message": "WKPreferences.javaScriptCanOpenWindowsAutomatically is set to true, so page script can open windows without a user gesture; leave it false unless the app must support script-opened windows from trusted content",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_uiwebview_re := `(?:^|[^\w])UIWebView\b(?:[^.\w]|$|\.[a-z])`

_uiwebview_line(line) if {
	not helpers.is_comment_line(line)
	regex.match(_uiwebview_re, _strip(line))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	contains(content, "UIWebView")
	lines := split(content, "\n")
	hits := [j | some j, l in lines; contains(l, "UIWebView"); _uiwebview_line(l)]
	count(hits) > 0
	i := min(hits)
	finding := {
		"rule_id": metadata.id,
		"message": "UIWebView is deprecated: it always runs JavaScript, offers no content isolation and is rejected by App Store review; migrate to WKWebView and keep JavaScript and file access off unless required",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

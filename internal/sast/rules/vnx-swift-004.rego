package vulnetix.rules.vnx_swift_004

import rego.v1

metadata := {
	"id": "VNX-SWIFT-004",
	"name": "Swift TLS certificate validation disabled in URLSession or AlamoFire",
	"description": "TLS certificate validation is explicitly disabled by implementing URLSessionDelegate to always trust certificates, or by passing insecure session configuration. This makes the app vulnerable to man-in-the-middle attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-004/",
	"languages": ["swift"],
	"severity": "high",
	"level": "error",
	"kind": "open",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:H/IC:H/FC:H/RP:H/RL:H/AV:N/AS:L/IN:L/SC:N/CONF:N/T:A/P:H",
	"tags": ["tls", "certificate-validation", "swift", "ios"],
}

_is_swift(path) if endswith(path, ".swift")

# URLCredential(trust:) always trusts any server certificate
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "URLCredential(trust:")
	finding := {
		"rule_id": metadata.id,
		"message": "URLCredential(trust:) bypasses TLS certificate validation; perform proper certificate evaluation and only trust valid chain certificates to prevent MITM attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# completionHandler(.useCredential, ...) in auth challenge delegate
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	contains(line, "completionHandler(.useCredential")
	window_start := max([0, i - 10])
	window_end := min([count(lines) - 1, i + 2])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	contains(window, "didReceive challenge")
	not contains(window, "serverTrust")
	finding := {
		"rule_id": metadata.id,
		"message": "URLSession auth challenge completed with .useCredential without verifying server trust; evaluate the server certificate chain before accepting credentials",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# AlamoFire ServerTrustPolicy.disableEvaluation
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_swift(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`disableEvaluation|DisableTrustEvaluation|\.disabled`, line)
	window_start := max([0, i - 5])
	window_end := min([count(lines) - 1, i + 5])
	window_lines := array.slice(lines, window_start, window_end + 1)
	window := concat("\n", window_lines)
	regex.match(`ServerTrustPolicy|ServerTrustEvaluating|TrustEvaluation`, window)
	finding := {
		"rule_id": metadata.id,
		"message": "TLS server trust evaluation disabled in AlamoFire/URLSession; configure a proper pinned certificate or CA evaluation policy to prevent MITM attacks",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

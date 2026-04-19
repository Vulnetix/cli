# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_918

import rego.v1

metadata := {
	"id": "VNX-918",
	"name": "Server-Side Request Forgery (SSRF)",
	"description": "Making HTTP requests to URLs derived from user input without validation enables Server-Side Request Forgery. Attackers can pivot to internal services, cloud metadata APIs, or arbitrary hosts.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-918/",
	"languages": ["python", "java", "php", "ruby", "node", "go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [918],
	"capec": ["CAPEC-664"],
	"attack_technique": ["T1090"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["ssrf", "injection", "network"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"requests.get(user",
	"requests.post(user",
	"requests.get(req.",
	"requests.get(url",
	"urllib.urlopen(user",
	"urllib.request.urlopen(user",
	"fetch(req.query",
	"fetch(req.body",
	"fetch(req.params",
	"axios.get(req.",
	"axios.post(req.",
	"http.get(req.",
	"new URL(userInput",
	"new URL(req.",
	"file_get_contents($url",
	"file_get_contents($_",
	"CURLOPT_URL, $user",
	"CURLOPT_URL, $_",
	"Net::HTTP.get(URI(user",
	"Net::HTTP.get(URI(params",
	"http.Get(userURL",
	"http.Get(r.URL",
	"http.Get(r.FormValue",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _patterns
	contains(line, p)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Potential SSRF: HTTP request using pattern '%v' may be constructed from user-controlled input", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_319

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-319",
	"name": "Cleartext Transmission of Sensitive Information",
	"description": "A real http:// or ftp:// endpoint is embedded in code: a URL with a registered host name. Not reported: the bare scheme used in a prefix check or a scheme list, loopback and reserved example hosts, XML/JSON-schema namespace identifiers that are names rather than endpoints (w3.org, cyclonedx.org, spdx.org), a normaliser that lists both the http and https form of one host, and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-319/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [319],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["cleartext-transmission", "cwe-319"],
}

_skip(path) if endswith(path, ".lock")

_skip(path) if endswith(path, ".sum")

_skip(path) if endswith(path, ".min.js")

_skip(path) if endswith(path, ".min.css")

_skip(path) if endswith(path, ".min.html")

# A scheme followed by a host that has a dot in it. `"http://"` alone, as in
# strings.HasPrefix(u, "http://"), has no host and is not an endpoint.
_url := `\b(?:http|ftp)://([A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9\-]+)+)`

# Hosts that are names, not endpoints, or that are not reachable at all.
_benign_host(h) if regex.match(`(?i)^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.)`, h)

_benign_host(h) if regex.match(`(?i)(\.(test|invalid|example|local|localhost|internal|lan)$|(^|\.)example\.(com|org|net)$)`, h)

# Namespace and schema identifiers: XML namespaces, JSON-schema $id, RDF terms.
_benign_host(h) if regex.match(`(?i)(^|\.)(w3\.org|cyclonedx\.org|spdx\.org|ns\.adobe\.com|purl\.org|json-schema\.org|schemas\.microsoft\.com|schemas\.xmlsoap\.org|xmlpull\.org|java\.sun\.com|maven\.apache\.org|xmlns\.com|ogp\.me)$`, h)

# The line is testing or rewriting a scheme, not using an endpoint.
_scheme_handling(line) if regex.match(`(HasPrefix|TrimPrefix|CutPrefix|HasSuffix|startswith|startsWith|\.contains\(|strings\.Contains|re\.compile|regexp\.|ReplaceAll|\.replace\()`, line)

# A normaliser lists both forms of one host: ["https://github.com/", "http://github.com/"].
_https_twin(line, h) if contains(line, concat("", ["https://", h]))

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	not helpers.is_test_path(path)
	some _ext in {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".java", ".go", ".php", ".rb"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	not _scheme_handling(line)
	some hit in regex.find_all_string_submatch_n(_url, line, 5)
	host := hit[1]
	not _benign_host(host)
	not _https_twin(line, host)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cleartext URL to %s — use HTTPS/SFTP", [host]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

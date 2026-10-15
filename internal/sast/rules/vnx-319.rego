# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_319

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-319",
	"name": "Cleartext Transmission of Sensitive Information",
	"description": "The program talks to a remote endpoint over cleartext http://, ws:// or ftp://, so requests, credentials and responses travel unencrypted. Reported: a URL with a registered host name on a line that uses it as an endpoint (or as an argument on its own line of a client call opened within two lines above): passed to an HTTP, FTP or socket client (requests/httpx/urllib/aiohttp, fetch, axios, jQuery ajax, XMLHttpRequest, WebSocket, EventSource, Go http.Get/Post/NewRequest, Java new URL/URI.create/HttpRequest/OkHttp .url()/RestTemplate/WebClient/HttpGet, PHP curl/file_get_contents/fopen/Guzzle/wp_remote_*, Ruby Net::HTTP/URI.parse/open-uri/HTTParty/Faraday/RestClient), assigned to a name or key that says it is an endpoint (url, uri, endpoint, host, server, base, api, webhook, callback, origin, proxy, registry, gateway, service, upstream, redirect), or loaded by a <script> or <iframe> src. Not reported: hyperlinks (href, link helpers), URLs in comments, licence headers and prose strings, lists of URLs with no endpoint context (redirect allowlists), XML/JSON-schema namespace and feature identifiers (w3.org, xml.org, apache.org features), the bare scheme in a prefix check or scheme list, loopback, private-range and reserved example hosts, a normaliser that lists both the http and https form of one host, test code, and example, sample and demo directories.",
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

_exts := {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".java", ".go", ".php", ".rb"}

_ext_ok(path) if {
	some e in _exts
	endswith(path, e)
	not endswith(path, ".min.js")
}

# A scheme followed by a host that has a dot in it. `"http://"` alone, as in
# strings.HasPrefix(u, "http://"), has no host and is not an endpoint.
_url := `\b(?:http|ftp|ws)://([A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9\-]+)+)`

# Hosts that are names, not endpoints, or that are not reachable at all.
_benign_host(h) if regex.match(`(?i)^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)`, h)

_benign_host(h) if regex.match(`(?i)(\.(test|invalid|example|local|localhost|internal|lan)$|(^|\.)example\.(com|org|net)$)`, h)

# Namespace and schema identifiers: XML namespaces, JSON-schema $id, RDF terms, SAX features.
_benign_host(h) if regex.match(`(?i)(^|\.)(w3\.org|cyclonedx\.org|spdx\.org|ns\.adobe\.com|purl\.org|json-schema\.org|schemas\.microsoft\.com|schemas\.xmlsoap\.org|xmlpull\.org|xml\.org|java\.sun\.com|maven\.apache\.org|xmlns\.com|ogp\.me|schemas\.android\.com|opensource\.org)$`, h)

# The line is testing or rewriting a scheme, not using an endpoint.
_scheme_handling(line) if regex.match(`(HasPrefix|TrimPrefix|CutPrefix|HasSuffix|startswith|startsWith|\.contains\(|strings\.Contains|re\.compile|regexp\.|ReplaceAll|\.replace\(|setFeature|setProperty\(\s*["']http)`, line)

# A normaliser lists both forms of one host: ["https://github.com/", "http://github.com/"].
_https_twin(line, h) if contains(line, concat("", ["https://", h]))

# A hyperlink is navigation, not a transmission the program makes.
_link(line) if regex.match(`(?i)(href\s*=|link_to|LinkUrl|\blink\(|<a\s)`, line)

# The URL is handed to a client.
_client := `(?i)(\brequests\.(get|post|put|patch|delete|head|options|request)\(|\.session\(\)\.(get|post)|urlopen\(|urllib\w*\.request|\bhttpx\.|aiohttp|ClientSession|\bfetch\(|\baxios(\.\w+)?\(|\$\.(ajax|get|post|getJSON)\(|XMLHttpRequest|\.open\(\s*['"](GET|POST|PUT|DELETE)['"]|new\s+(WebSocket|EventSource|URL|HttpGet|HttpPost|HttpPut|Socket)\(|\bio\(|\bhttp\.(Get|Post|PostForm|Head|NewRequest\w*)\(|NewRequest(WithContext)?\(|\.Dial\w*\(|URI\.create\(|HttpRequest\.newBuilder|\.url\(|\.uri\(|\.baseUrl\(|getForObject|postForObject|getForEntity|postForEntity|\.exchange\(|WebClient|openConnection|Net::HTTP|URI\.parse|URI\(|\bopen\(\s*['"]|HTTParty|Faraday|RestClient|curl_init|curl_setopt|file_get_contents\(|fopen\(|->request\(|->get\(|->post\(|wp_remote_|ftp_connect|FTPClient|ftplib|\.connect\(|\.get\(\s*['"\x60](?:http|ftp)://|\.post\(\s*['"\x60](?:http|ftp)://)`

# The URL is the value of a name or key that says it is an endpoint.
_endpoint_assign := "(?i)\\b\\w*(url|uri|endpoint|host|server|base|api|webhook|callback|origin|proxy|registry|gateway|service|remote|upstream|redirect|ftp)s?\\w*['\"]?\\]?\\s*(?::=|=|:|=>)\\s*(?:\\[\\s*)?(?:[A-Za-z_.]+\\(\\s*)?[rfbu]?['\"`](?:http|ftp|ws)://"

# <script src="http://..."> and <iframe src="http://..."> load code or pages in cleartext.
_markup_load := `(?i)<(script|iframe)\b[^>]*\bsrc\s*=\s*["']?(?:http|ftp)://`

_endpoint_context(line) if regex.match(_client, line)

_endpoint_context(line) if regex.match(_endpoint_assign, line)

_endpoint_context(line) if regex.match(_markup_load, line)

# The URL is an argument on its own line of a call opened just above:
#     req, err := http.NewRequest(
#         http.MethodPost,
#         "http://host/ingest",
_endpoint_ctx(lines, i, line) if _endpoint_context(line)

_endpoint_ctx(lines, i, line) if {
	regex.match("^\\s*[rfbu]?['\"`](?:http|ftp|ws)://", line)
	some j in numbers.range(max([0, i - 2]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(`[(,]\s*$`, lines[j])
	regex.match(_client, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	not helpers.is_test_path(path)
	not regex.match(`(^|/)(examples?|samples?|demos?)/`, path)
	regex.match(`\b(http|ftp|ws)://[A-Za-z0-9]`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(http|ftp|ws)://[A-Za-z0-9]`, line)
	not helpers.is_comment_line(line)
	not _scheme_handling(line)
	not _link(line)
	_endpoint_ctx(lines, i, line)
	some hit in regex.find_all_string_submatch_n(_url, line, 5)
	host := hit[1]
	not _benign_host(host)
	not _https_twin(line, host)
	not _after_comment_marker(line, host)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cleartext URL to %s: use HTTPS/SFTP", [host]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The URL sits in a trailing comment: x = 1 // see http://host/...
_after_comment_marker(line, host) if {
	idx := indexof(line, concat("", ["://", host]))
	before := substring(line, 0, idx)
	regex.match(`(^|\s)(//|#)\s|/\*`, before)
	not regex.match(`['"\x60][^'"\x60]*$`, before)
}

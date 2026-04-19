# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_601

import rego.v1

metadata := {
	"id": "VNX-601",
	"name": "Open Redirect",
	"description": "Redirecting users to URLs derived from unvalidated request parameters enables phishing, credential theft, and OAuth token hijacking. Always validate redirect targets against an allowlist of trusted URLs or paths.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-601/",
	"languages": ["python", "java", "php", "ruby", "node", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1566"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["open-redirect", "phishing", "injection"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_patterns := {
	"HttpResponseRedirect(request.GET",
	"HttpResponseRedirect(request.POST",
	"redirect(request.GET",
	"redirect(request.POST",
	"redirect_to params[",
	"redirect_to params.fetch",
	"header(\"Location: \" . $_GET",
	"header(\"Location: \" . $_POST",
	"header(\"Location: \" . $",
	"response.sendRedirect(request.getParameter",
	"res.redirect(req.query",
	"res.redirect(req.body",
	"res.redirect(req.params",
	"http.Redirect(w, r, r.URL.Query()",
	"http.Redirect(w, r, r.FormValue(",
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
		"message": sprintf("Open redirect: '%v' redirects to a user-controlled URL without validation — validate against an allowlist", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

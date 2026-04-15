package vulnetix.rules.vnx_java_007

import rego.v1

metadata := {
	"id": "VNX-JAVA-007",
	"name": "Java open redirect",
	"description": "Passing user-controlled input (request.getParameter) directly to response.sendRedirect() or ModelAndView redirect allows attackers to redirect users to malicious sites for phishing.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-007/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "open",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1566"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["open-redirect", "web", "phishing"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

_redirect_indicators := {
	"sendRedirect(request.getParameter",
	"sendRedirect(req.getParameter",
	"redirect:\" + request.getParameter",
	"new ModelAndView(\"redirect:\" + ",
	"RedirectView(request.getParameter",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some indicator in _redirect_indicators
	contains(line, indicator)
	finding := {
		"rule_id": metadata.id,
		"message": "User input passed directly to redirect; validate the URL against an allowlist of trusted domains",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

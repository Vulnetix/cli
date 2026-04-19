package vulnetix.rules.vnx_go_025

import rego.v1

metadata := {
    "id": "VNX-GO-025",
    "name": "Potential open redirect via HTTP redirect",
    "description": "Using user-controlled input in HTTP redirect URLs without validation can lead to open redirect vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-025/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [601],
    "capec": ["CAPEC-610"],
    "attack_technique": ["T1046"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["open-redirect", "http", "redirect"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for http.Redirect or similar with user input
    (contains(line, "http.Redirect") or
     contains(line, "Redirect") or
     contains(line, "http.RedirectHandler")) and
    (contains(line, "r.FormValue") or
     contains(line, "r.URL.Query") or
     contains(line, "r.PostFormValue") or
     contains(line, "r.Header.Get") or
     contains(line, "ctx.Value"))
    // And no validation/sanitization
    not (contains(line, "validation.") or
         contains(line, "validate.") or
         contains(line, "isSafeURL") or
         contains(line, "IsSafeURL") or
         contains(line, "sanitize."))
    finding := {
        "rule_id": metadata.id,
        "message": "HTTP redirect with user input may lead to open redirect; validate the URL",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
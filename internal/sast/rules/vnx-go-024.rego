package vulnetix.rules.vnx_go_024

import rego.v1

metadata := {
    "id": "VNX-GO-024",
    "name": "Missing input validation on HTTP request parameters",
    "description": "Using HTTP request parameters directly without validation can lead to various injection and business logic bypass vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-024/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [20],
    "capec": ["CAPEC-101"],
    "attack_technique": ["T1195"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["input-validation", "http", "request"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for direct use of request params like r.FormValue, r.URL.Query().Get, etc.
    (contains(line, "r.FormValue(") ||
     contains(line, "r.URL.Query().Get(") ||
     contains(line, "r.PostFormValue(") ||
     contains(line, "r.Header.Get(") ||
     contains(line, "ctx.Value("))
    // And no validation/sanitization calls nearby (simple check)
    not (contains(line, "validation.") ||
         contains(line, "validate.") ||
         contains(line, "sanitize.") ||
         contains(line, "html.EscapeString") ||
         contains(line, "template.HTMLEscapeString"))
    finding := {
        "rule_id": metadata.id,
        "message": "HTTP request parameter used without apparent validation; consider validating input",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
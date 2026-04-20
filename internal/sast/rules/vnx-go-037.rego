package vulnetix.rules.vnx_go_037

import rego.v1

metadata := {
    "id": "VNX-GO-037",
    "name": "Missing security headers in HTTP response",
    "description": "Missing security headers such as X-Frame-Options, X-Content-Type-Options, etc. can leave the application vulnerable to various attacks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-037/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [693],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["headers", "security", "http"],
}

_is_go(path) if endswith(path, ".go")

_writes_response(line) if contains(line, "WriteHeader")
_writes_response(line) if contains(line, "Header().Set")
_writes_response(line) if contains(line, "http.ResponseWriter")

_security_headers := {
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
}

_has_security_header(content) if {
    some h in _security_headers
    contains(content, h)
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    content := input.file_contents[path]
    not _has_security_header(content)
    lines := split(content, "\n")
    some i, line in lines
    _writes_response(line)
    finding := {
        "rule_id": metadata.id,
        "message": "HTTP response headers set without common security headers (e.g., X-Frame-Options, X-Content-Type-Options); consider adding them",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}

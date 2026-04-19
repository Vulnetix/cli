package vulnetix.rules.vnx_go_030

import rego.v1

metadata := {
    "id": "VNX-GO-030",
    "name": "Missing Secure flag on cookie",
    "description": "Cookies that are not marked as Secure can be transmitted over unencrypted connections, exposing them to interception.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-030/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [614],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["cookie", "secure", "session"],
}

_is_go(path) if endswith(path, ".go")

_has_cookie(line) if contains(line, "http.Cookie")
_has_cookie(line) if contains(line, "&http.Cookie")
_has_cookie(line) if contains(line, "cookie := &http.Cookie")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for cookie setting without Secure
    _has_cookie(line)
    not contains(line, "Secure: true")
    finding := {
        "rule_id": metadata.id,
        "message": "Cookie set without Secure flag; consider adding Secure:true to prevent transmission over unencrypted connections",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
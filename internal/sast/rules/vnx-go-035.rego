package vulnetix.rules.vnx_go_035

import rego.v1

metadata := {
    "id": "VNX-GO-035",
    "name": "Missing HttpOnly flag on cookie",
    "description": "Cookies that are not marked as HttpOnly can be accessed by client-side scripts, increasing the risk of XSS attacks stealing session tokens.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-035/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [1004],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["cookie", "httponly", "session"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for cookie setting without HttpOnly
    (contains(line, "http.Cookie") or contains(line, "&http.Cookie") or contains(line, "cookie := &http.Cookie")) and
    not contains(line, "HttpOnly: true")
    finding := {
        "rule_id": metadata.id,
        "message": "Cookie set without HttpOnly flag; consider adding HttpOnly:true to prevent client-side script access",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
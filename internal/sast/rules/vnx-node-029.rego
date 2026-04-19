package vulnetix.rules.vnx_node_029

import rego.v1

metadata := {
    "id": "VNX-NODE-029",
    "name": "Missing HttpOnly flag on cookie",
    "description": "Cookies that are not marked as HttpOnly can be accessed by client-side scripts, increasing the risk of XSS attacks stealing session tokens.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-029/",
    "languages": ["node", "javascript"],
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

_is_js_file(path) if endswith(path, ".js")
_is_js_file(path) if endswith(path, ".ts")

_has_cookie_call(line) if contains(line, "cookie(")
_has_cookie_call(line) if contains(line, ".cookie(")
_has_cookie_call(line) if contains(line, "res.cookie(")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_js_file(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for cookie setting without HttpOnly
    _has_cookie_call(line)
    not contains(line, "httpOnly")
    finding := {
        "rule_id": metadata.id,
        "message": "Cookie set without HttpOnly flag; consider adding httpOnly:true to prevent client-side script access",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
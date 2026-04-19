package vulnetix.rules.vnx_node_028

import rego.v1

metadata := {
    "id": "VNX-NODE-028",
    "name": "Missing Content-Security-Policy header",
    "description": "Missing Content-Security-Policy header can leave the application vulnerable to XSS and data injection attacks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-028/",
    "languages": ["node", "javascript"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [693],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["csp", "header", "security"],
}

_is_js_file(path) if endswith(path, ".js")
_is_js_file(path) if endswith(path, ".ts")

_has_header_call(line) if contains(line, ".writeHead")
_has_header_call(line) if contains(line, ".setHeader")
_has_header_call(line) if contains(line, ".header(")

_has_csp(line) if contains(line, "Content-Security-Policy")
_has_csp(line) if contains(line, "X-Content-Security-Policy")
_has_csp(line) if contains(line, "X-WebKit-CSP")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_js_file(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for HTTP response setting without CSP header
    _has_header_call(line)
    # Simple check: if we see response headers being set but no CSP
    not _has_csp(line)
    finding := {
        "rule_id": metadata.id,
        "message": "HTTP response headers set without Content-Security-Policy; consider adding CSP header",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
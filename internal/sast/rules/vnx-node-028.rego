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

findings contains finding if {
    some path in object.keys(input.file_contents)
    (endswith(path, ".js") || endswith(path, ".ts"))
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for HTTP response setting without CSP header
    contains(line, ".writeHead") or contains(line, ".setHeader") or contains(line, ".header(")
    // Simple check: if we see response headers being set but no CSP
    not (contains(line, "Content-Security-Policy") or contains(line, "X-Content-Security-Policy") or contains(line, "X-WebKit-CSP"))
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
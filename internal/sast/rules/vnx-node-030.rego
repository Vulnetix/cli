package vulnetix.rules.vnx_node_030

import rego.v1

metadata := {
    "id": "VNX-NODE-030",
    "name": "TURN server allowing reserved IP addresses",
    "description": "Allowing TURN server access to reserved IP addresses (like localhost, private IPs) can lead to security vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-030/",
    "languages": ["node", "javascript"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [200],
    "capec": ["CAPEC-200"],
    "attack_technique": ["T1046"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["webrtc", "turn", "ip-address", "security"],
}

_is_js_file(path) if endswith(path, ".js")
_is_js_file(path) if endswith(path, ".ts")

_has_filter(line) if contains(line, ".filter(")
_has_filter(line) if contains(line, ".includes(")
_has_filter(line) if contains(line, ".indexOf(")
_has_filter(line) if contains(line, "===")
_has_filter(line) if contains(line, "!==")

_has_reserved_ip(line) if contains(line, "127.0.0.1")
_has_reserved_ip(line) if contains(line, "localhost")
_has_reserved_ip(line) if contains(line, "10.")
_has_reserved_ip(line) if contains(line, "192.168.")
_has_reserved_ip(line) if contains(line, "172.16.")
_has_reserved_ip(line) if contains(line, "172.31.")
_has_reserved_ip(line) if contains(line, "169.254.")
_has_reserved_ip(line) if contains(line, "0.0.0.0")
_has_reserved_ip(line) if contains(line, "255.255.255.255")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_js_file(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for IP address validation or filtering
    _has_filter(line)
    # Check for reserved IP patterns
    _has_reserved_ip(line)
    # Not properly excluded with !=
    not (contains(line, "!=") and _has_reserved_ip(line))
    finding := {
        "rule_id": metadata.id,
        "message": "IP address check may allow reserved IPs (localhost, private ranges); TURN server should not allow access to reserved IP addresses",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
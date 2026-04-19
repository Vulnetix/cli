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

findings contains finding if {
    some path in object.keys(input.file_contents)
    (endswith(path, ".js") || endswith(path, ".ts"))
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for IP address validation or filtering
    (contains(line, ".filter(") or
     contains(line, ".includes(") or
     contains(line, ".indexOf(") or
     contains(line, "===") or
     contains(line, "!==")) and
    // Check for reserved IP patterns: localhost, private ranges, etc.
    (contains(line, "127.0.0.1") or
     contains(line, "localhost") or
     contains(line, "10.") or
     contains(line, "192.168.") or
     contains(line, "172.16.") or
     contains(line, "172.31.") or
     contains(line, "169.254.") or
     contains(line, "0.0.0.0") or
     contains(line, "255.255.255.255")) and
    // The context seems to be allowing these IPs (negative logic: we want to flag when they are ALLOWED)
    // This is tricky; we'll look for lack of negation or exclusion
    not (contains(line, "!=") and
         (contains(line, "127.0.0.1") or
          contains(line, "localhost") or
          contains(line, "10.") or
          contains(line, "192.168.") or
          contains(line, "172.16.") or
          contains(line, "172.31.") or
          contains(line, "169.254.") or
          contains(line, "0.0.0.0") or
          contains(line, "255.255.255.255")))
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
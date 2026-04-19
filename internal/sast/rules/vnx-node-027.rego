package vulnetix.rules.vnx_node_027

import rego.v1

metadata := {
    "id": "VNX-NODE-027",
    "name": "Assignment to innerHTML without sanitization",
    "description": "Direct assignment to innerHTML property can lead to Cross-Site Scripting (XSS) vulnerabilities if the assigned value contains user-controlled data.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-027/",
    "languages": ["node", "javascript"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [79],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["xss", "innerhtml", "dom"],
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    endswith(path, ".js")
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    contains(line, ".innerHTML =")
    finding := {
        "rule_id": metadata.id,
        "message": "Assignment to innerHTML can lead to XSS if the value is not properly sanitized",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
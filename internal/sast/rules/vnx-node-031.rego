package vulnetix.rules.vnx_node_031

import rego.v1

metadata := {
    "id": "VNX-NODE-031",
    "name": "Logging of sensitive data",
    "description": "Logging sensitive data such as passwords, tokens, or personal information can lead to information disclosure.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-031/",
    "languages": ["node", "javascript"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [532],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["logging", "sensitive-data", "information-disclosure"],
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    (endswith(path, ".js") || endswith(path, ".ts"))
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for logging functions
    (contains(line, "console.log") or
     contains(line, "console.info") or
     contains(line, "console.warn") or
     contains(line, "console.error") or
     contains(line, "logger.") or
     contains(line, "winston.") or
     contains(line, "bunyan.") or
     contains(line, "pino.")) and
    // Check if any sensitive data patterns are in the line
    (contains(line, "password") or
     contains(line, "passwd") or
     contains(line, "secret") or
     contains(line, "token") or
     contains(line, "auth") or
     contains(line, "credit") or
     contains(line, "card") or
     contains(line, "cvv") or
     contains(line, "ssn") or
     contains(line, "pin"))
    finding := {
        "rule_id": metadata.id,
        "message": "Potential logging of sensitive data",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
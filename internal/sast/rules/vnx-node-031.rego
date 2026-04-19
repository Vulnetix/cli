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

_is_js_file(path) if endswith(path, ".js")
_is_js_file(path) if endswith(path, ".ts")

_has_logging(line) if contains(line, "console.log")
_has_logging(line) if contains(line, "console.info")
_has_logging(line) if contains(line, "console.warn")
_has_logging(line) if contains(line, "console.error")
_has_logging(line) if contains(line, "logger.")
_has_logging(line) if contains(line, "winston.")
_has_logging(line) if contains(line, "bunyan.")
_has_logging(line) if contains(line, "pino.")

_has_sensitive_data(line) if contains(line, "password")
_has_sensitive_data(line) if contains(line, "passwd")
_has_sensitive_data(line) if contains(line, "secret")
_has_sensitive_data(line) if contains(line, "token")
_has_sensitive_data(line) if contains(line, "auth")
_has_sensitive_data(line) if contains(line, "credit")
_has_sensitive_data(line) if contains(line, "card")
_has_sensitive_data(line) if contains(line, "cvv")
_has_sensitive_data(line) if contains(line, "ssn")
_has_sensitive_data(line) if contains(line, "pin")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_js_file(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for logging functions
    _has_logging(line)
    # Check if any sensitive data patterns are in the line
    _has_sensitive_data(line)
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
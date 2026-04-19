package vulnetix.rules.vnx_go_040

import rego.v1

metadata := {
    "id": "VNX-GO-040",
    "name": "Logging of sensitive data",
    "description": "Logging sensitive data such as passwords, tokens, or personal information can lead to information disclosure.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-040/",
    "languages": ["go"],
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

_is_go(path) if endswith(path, ".go")

# Patterns that indicate sensitive data
sensitive_patterns := [
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "key",
    "token",
    "auth",
    "credential",
    "pin",
    "ssn",
    "social",
    "credit",
    "card",
    "cvv",
    "cvc",
    "account",
    "iban",
    "routing",
]

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for logging functions
    (contains(line, "log.Print") or
     contains(line, "log.Println") or
     contains(line, "log.Printf") or
     contains(line, "logrus.") or
     contains(line, "zap.") or
     contains(line, "zerolog.") or
     contains(line, "logger.")) and
    // Check if any sensitive data patterns are in the line
    some sensitive in sensitive_patterns
    contains(line, sensitive)
    finding := {
        "rule_id": metadata.id,
        "message": "Potential logging of sensitive data: " + sensitive,
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
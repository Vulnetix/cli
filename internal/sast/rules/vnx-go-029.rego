package vulnetix.rules.vnx_go_029

import rego.v1

metadata := {
    "id": "VNX-GO-029",
    "name": "Hardcoded weak or default password",
    "description": "Hardcoded weak or default passwords (such as 'admin', 'password', '123456') are susceptible to brute force attacks and should not be used in production code.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-029/",
    "languages": ["go"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [798],
    "capec": ["CAPEC-256"],
    "attack_technique": ["T1078.003"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["hardcoded-password", "weak-password", "credentials"],
}

_is_go(path) if endswith(path, ".go")

# List of common weak/default passwords
weak_passwords := [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "michael",
    "superman",
    "1qaz2wsx",
    "password1",
    "admin",
    "administrator",
    "root",
    "sa",
    "sys",
    "guest",
    "user",
    "test",
    "demo",
]

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for assignment of a string literal to a variable that looks like a password
    (contains(line, ":=") or contains(line, "=")) and
    (contains(line, "password") or contains(line, "passwd") or contains(line, "pass") or contains(line, "pwd")) and
    # Extract the string literal on the right side
    # We'll do a simple check: if the line contains a quote and the string inside is in our weak_passwords list
    some weak in weak_passwords
    contains(line, `"` + weak + `"`) or contains(line, "`" + weak + "`") or contains(line, "'" + weak + "'")
    finding := {
        "rule_id": metadata.id,
        "message": "Hardcoded weak or default password detected: " + weak,
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
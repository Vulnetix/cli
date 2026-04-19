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

_has_assign(line) if contains(line, ":=")
_has_assign(line) if contains(line, "=")

_has_password_var(line) if contains(line, "password")
_has_password_var(line) if contains(line, "passwd")
_has_password_var(line) if contains(line, "pass")
_has_password_var(line) if contains(line, "pwd")

_has_weak_password(line) if contains(line, "123456")
_has_weak_password(line) if contains(line, "password")
_has_weak_password(line) if contains(line, "12345678")
_has_weak_password(line) if contains(line, "qwerty")
_has_weak_password(line) if contains(line, "123456789")
_has_weak_password(line) if contains(line, "12345")
_has_weak_password(line) if contains(line, "1234")
_has_weak_password(line) if contains(line, "111111")
_has_weak_password(line) if contains(line, "1234567")
_has_weak_password(line) if contains(line, "dragon")
_has_weak_password(line) if contains(line, "123123")
_has_weak_password(line) if contains(line, "baseball")
_has_weak_password(line) if contains(line, "abc123")
_has_weak_password(line) if contains(line, "football")
_has_weak_password(line) if contains(line, "monkey")
_has_weak_password(line) if contains(line, "letmein")
_has_weak_password(line) if contains(line, "shadow")
_has_weak_password(line) if contains(line, "master")
_has_weak_password(line) if contains(line, "666666")
_has_weak_password(line) if contains(line, "qwertyuiop")
_has_weak_password(line) if contains(line, "123321")
_has_weak_password(line) if contains(line, "mustang")
_has_weak_password(line) if contains(line, "michael")
_has_weak_password(line) if contains(line, "superman")
_has_weak_password(line) if contains(line, "1qaz2wsx")
_has_weak_password(line) if contains(line, "password1")
_has_weak_password(line) if contains(line, "admin")
_has_weak_password(line) if contains(line, "administrator")
_has_weak_password(line) if contains(line, "root")
_has_weak_password(line) if contains(line, "sa")
_has_weak_password(line) if contains(line, "sys")
_has_weak_password(line) if contains(line, "guest")
_has_weak_password(line) if contains(line, "user")
_has_weak_password(line) if contains(line, "test")
_has_weak_password(line) if contains(line, "demo")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    _has_assign(line)
    _has_password_var(line)
    _has_weak_password(line)
    finding := {
        "rule_id": metadata.id,
        "message": "Hardcoded weak or default password detected",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
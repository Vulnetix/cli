package vulnetix.rules.vnx_go_039

import rego.v1

metadata := {
    "id": "VNX-GO-039",
    "name": "Missing rate limiting on login endpoint",
    "description": "Login endpoints without rate limiting are vulnerable to brute force attacks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-039/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [307],
    "capec": ["CAPEC-49"],
    "attack_technique": ["T1110"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["rate-limiting", "brute-force", "login"],
}

_is_go(path) if endswith(path, ".go")

_has_login_keyword(line) if contains(line, "Login")
_has_login_keyword(line) if contains(line, "login")
_has_login_keyword(line) if contains(line, "SignIn")
_has_login_keyword(line) if contains(line, "signIn")
_has_login_keyword(line) if contains(line, "signin")

_is_login_handler(line) if {
    contains(line, "func ")
    _has_login_keyword(line)
}

_has_rate_limiting(line) if contains(line, "rate")
_has_rate_limiting(line) if contains(line, "throttle")
_has_rate_limiting(line) if contains(line, "limiter")
_has_rate_limiting(line) if contains(line, "RateLimit")
_has_rate_limiting(line) if contains(line, "Throttle")
_has_rate_limiting(line) if contains(line, "Limiter")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    _is_login_handler(line)
    not _has_rate_limiting(line)
    finding := {
        "rule_id": metadata.id,
        "message": "Login handler without apparent rate limiting; consider adding rate limiting to prevent brute force attacks",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
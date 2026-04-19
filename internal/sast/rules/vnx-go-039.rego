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

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for HTTP handler functions that might be login endpoints
    (contains(line, "func ") and
     (contains(line, "Login") ;
      contains(line, "login") ;
      contains(line, "SignIn") ;
      contains(line, "signIn") ;
      contains(line, "signin"))) and
    # Check if there's no rate limiting middleware or function call nearby (simple heuristic)
    # We'll look in the same function or the next few lines for rate limiting terms
    not (contains(line, "rate") ;
         contains(line, "throttle") ;
         contains(line, "limiter") ;
         contains(line, "RateLimit") ;
         contains(line, "Throttle") ;
         contains(line, "Limiter"))
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
package vulnetix.rules.vnx_go_037

import rego.v1

metadata := {
    "id": "VNX-GO-037",
    "name": "Missing security headers in HTTP response",
    "description": "Missing security headers such as X-Frame-Options, X-Content-Type-Options, etc. can leave the application vulnerable to various attacks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-037/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [693],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["headers", "security", "http"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for HTTP response writing without setting common security headers
    (contains(line, "WriteHeader") ;
     contains(line, "Header().Set") ;
     contains(line, "WriteHeader") ;
     contains(line, "http.ResponseWriter")) and
    # Check if we are setting headers but missing some important ones
    # We'll do a simple check: if we see any header setting, but not the specific ones we care about
    # This is a heuristic and might have false positives/negatives.
    not (contains(line, "X-Frame-Options") ;
         contains(line, "X-Content-Type-Options") ;
         contains(line, "X-XSS-Protection") ;
         contains(line, "Strict-Transport-Security") ;
         contains(line, "Content-Security-Policy") ;
         contains(line, "Referrer-Policy") ;
         contains(line, "Permissions-Policy"))
    finding := {
        "rule_id": metadata.id,
        "message": "HTTP response headers set without common security headers (e.g., X-Frame-Options, X-Content-Type-Options); consider adding them",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
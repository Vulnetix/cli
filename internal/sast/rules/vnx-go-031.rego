package vulnetix.rules.vnx_go_031

import rego.v1

metadata := {
    "id": "VNX-GO-031",
    "name": "Missing signature validation on JWT",
    "description": "Using JWT tokens without validating the signature can lead to token forgery and unauthorized access.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-031/",
    "languages": ["go"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [347],
    "capec": ["CAPEC-64"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["jwt", "token", "signature", "authentication"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for JWT parsing/usage without validation
    (contains(line, "jwt.Parse") or
     contains(line, "jwt.Decode") or
     contains(line, "jwt.DecodeSegment")) and
    // Check if there's no validation method called
    not (contains(line, "VerifySignature") or
         contains(line, "Validate") or
         contains(line, "Valid") or
         contains(line, "ParseWithClaims") or
         contains(line, "jwt.ParseRSAPublicKeyFromPEM") or
         contains(line, "jwt.ParseECPublicKeyFromPEM"))
    finding := {
        "rule_id": metadata.id,
        "message": "JWT token used without apparent signature validation; consider validating the token signature",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
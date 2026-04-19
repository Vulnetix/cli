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

_has_jwt_parse(line) if contains(line, "jwt.Parse")
_has_jwt_parse(line) if contains(line, "jwt.Decode")
_has_jwt_parse(line) if contains(line, "jwt.DecodeSegment")

_has_validation(line) if contains(line, "VerifySignature")
_has_validation(line) if contains(line, "Validate")
_has_validation(line) if contains(line, "Valid")
_has_validation(line) if contains(line, "ParseWithClaims")
_has_validation(line) if contains(line, "jwt.ParseRSAPublicKeyFromPEM")
_has_validation(line) if contains(line, "jwt.ParseECPublicKeyFromPEM")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for JWT parsing/usage without validation
    _has_jwt_parse(line)
    not _has_validation(line)
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
package vulnetix.rules.vnx_go_032

import rego.v1

metadata := {
    "id": "VNX-GO-032",
    "name": "JWT missing expiration validation",
    "description": "Using JWT tokens without validating the expiration time can lead to accepting expired tokens.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-032/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [613],
    "capec": ["CAPEC-64"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["jwt", "token", "expiration", "authentication"],
}

_is_go(path) if endswith(path, ".go")

_has_jwt_parse(line) if contains(line, "jwt.Parse")
_has_jwt_parse(line) if contains(line, "jwt.Decode")
_has_jwt_parse(line) if contains(line, "jwt.DecodeSegment")

_has_expiration_check(line) if contains(line, "VerifyExpiresAt")
_has_expiration_check(line) if contains(line, "Validate")
_has_expiration_check(line) if contains(line, "Valid")
_has_expiration_check(line) if contains(line, "Claims.ExpiresAt")
_has_expiration_check(line) if contains(line, "StandardClaims.ExpiresAt")
_has_expiration_check(line) if contains(line, "RegisteredClaims.ExpiresAt")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    _has_jwt_parse(line)
    not _has_expiration_check(line)
    finding := {
        "rule_id": metadata.id,
        "message": "JWT token used without apparent expiration validation; consider validating the token expiration",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
package vulnetix.rules.vnx_go_033

import rego.v1

metadata := {
    "id": "VNX-GO-033",
    "name": "JWT missing audience validation",
    "description": "Using JWT tokens without validating the audience (aud) claim can lead to token being used for an unintended service.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-033/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [347],
    "capec": ["CAPEC-64"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["jwt", "token", "audience", "authentication"],
}

_is_go(path) if endswith(path, ".go")

_has_jwt_parse(line) if contains(line, "jwt.Parse")
_has_jwt_parse(line) if contains(line, "jwt.Decode")
_has_jwt_parse(line) if contains(line, "jwt.DecodeSegment")

_has_audience_validation(line) if contains(line, "VerifyAudience")
_has_audience_validation(line) if contains(line, "ValidateAudience")
_has_audience_validation(line) if contains(line, "Claims.Audience")
_has_audience_validation(line) if contains(line, "StandardClaims.Audience")
_has_audience_validation(line) if contains(line, "RegisteredClaims.Audience")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for JWT parsing/usage without checking audience
    _has_jwt_parse(line)
    # Check if there's no audience validation
    not _has_audience_validation(line)
    finding := {
        "rule_id": metadata.id,
        "message": "JWT token used without apparent audience validation; consider validating the token audience",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
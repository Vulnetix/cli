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

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for JWT parsing/usage without checking audience
    (contains(line, "jwt.Parse") or
     contains(line, "jwt.Decode") or
     contains(line, "jwt.DecodeSegment")) and
    // Check if there's no audience validation
    not (contains(line, "VerifyAudience") or
         contains(line, "ValidateAudience") or
         contains(line, "Claims.Audience") or
         contains(line, "StandardClaims.Audience") or
         contains(line, "RegisteredClaims.Audience"))
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
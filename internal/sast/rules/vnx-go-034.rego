package vulnetix.rules.vnx_go_034

import rego.v1

metadata := {
    "id": "VNX-GO-034",
    "name": "OAuth redirect URI without validation against allowlist",
    "description": "Using a redirect URI from user input without validating it against an allowlist can lead to OAuth redirect URI manipulation attacks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-034/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [601],
    "capec": ["CAPEC-610"],
    "attack_technique": ["T1046"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["oauth", "redirect-uri", "validation", "allowlist"],
}

_is_go(path) if endswith(path, ".go")

_has_redirect(line) if contains(line, "http.Redirect")
_has_redirect(line) if contains(line, "Redirect")
_has_redirect(line) if contains(line, "http.RedirectHandler")

_has_user_input(line) if contains(line, "r.FormValue")
_has_user_input(line) if contains(line, "r.URL.Query")
_has_user_input(line) if contains(line, "r.PostFormValue")
_has_user_input(line) if contains(line, "r.Header.Get")
_has_user_input(line) if contains(line, "ctx.Value")

_has_validation(line) if contains(line, "allowlist")
_has_validation(line) if contains(line, "allowed")
_has_validation(line) if contains(line, "valid")
_has_validation(line) if contains(line, "validation.")
_has_validation(line) if contains(line, "validate.")
_has_validation(line) if contains(line, "sanitize.")
_has_validation(line) if contains(line, "isAllowed")
_has_validation(line) if contains(line, "isValid")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for http.Redirect or similar redirect functions
    _has_redirect(line)
    # Check if the redirect URI comes from a request parameter
    _has_user_input(line)
    # Check if there's no apparent validation
    not _has_validation(line)
    finding := {
        "rule_id": metadata.id,
        "message": "Redirect URI from user input used without validation against an allowlist; consider validating the redirect URI",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
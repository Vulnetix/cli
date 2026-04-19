package vulnetix.rules.vnx_go_025

import rego.v1

metadata := {
    "id": "VNX-GO-025",
    "name": "Potential open redirect via HTTP redirect",
    "description": "Using user-controlled input in HTTP redirect URLs without validation can lead to open redirect vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-025/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [601],
    "capec": ["CAPEC-610"],
    "attack_technique": ["T1046"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["open-redirect", "http", "redirect"],
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

_has_validation(line) if contains(line, "validation.")
_has_validation(line) if contains(line, "validate.")
_has_validation(line) if contains(line, "isSafeURL")
_has_validation(line) if contains(line, "IsSafeURL")
_has_validation(line) if contains(line, "sanitize.")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    _has_redirect(line)
    _has_user_input(line)
    not _has_validation(line)
    finding := {
        "rule_id": metadata.id,
        "message": "HTTP redirect with user input may lead to open redirect; validate the URL",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
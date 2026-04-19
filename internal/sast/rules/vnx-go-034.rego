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

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for http.Redirect or similar redirect functions
    (contains(line, "http.Redirect") ;
     contains(line, "Redirect") ;
     contains(line, "http.RedirectHandler")) and
    # Check if the redirect URI comes from a request parameter (user input)
    (contains(line, "r.FormValue") ;
     contains(line, "r.URL.Query") ;
     contains(line, "r.PostFormValue") ;
     contains(line, "r.Header.Get") ;
     contains(line, "ctx.Value")) and
    # Check if there's no apparent validation (like against an allowlist)
    not (contains(line, "allowlist") ;
         contains(line, "allowed") ;
         contains(line, "valid") ;
         contains(line, "validation.") ;
         contains(line, "validate.") ;
         contains(line, "sanitize.") ;
         contains(line, "isAllowed") ;
         contains(line, "isValid"))
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
package vulnetix.rules.vnx_go_027

import rego.v1

metadata := {
    "id": "VNX-GO-027",
    "name": "Potential path traversal via file path construction",
    "description": "Constructing file paths using user input without proper validation can lead to path traversal vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-027/",
    "languages": ["go"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [22],
    "capec": ["CAPEC-128"],
    "attack_technique": ["T1082"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["path-traversal", "file", "directory"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for path construction with user input
    (contains(line, "filepath.Join") ;
     contains(line, "path.Join") ;
     contains(line, "/") ;
     contains(line, "\\")) and
    (contains(line, "r.FormValue") ;
     contains(line, "r.URL.Query") ;
     contains(line, "r.PostFormValue") ;
     contains(line, "r.Header.Get") ;
     contains(line, "ctx.Value") ;
     contains(line, "os.Args"))
    # And no path validation/sanitization
    not (contains(line, "filepath.Clean") ;
         contains(line, "path.Clean") ;
         contains(line, "strings.Contains") and contains(line, "..") ;
         contains(line, "validation.") ;
         contains(line, "validate.") ;
         contains(line, "sanitize."))
    finding := {
        "rule_id": metadata.id,
        "message": "File path constructed with user input may lead to path traversal; validate and sanitize the path",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}

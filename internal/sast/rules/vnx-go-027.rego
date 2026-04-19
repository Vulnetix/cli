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
    // Look for path construction with user input
    (contains(line, "filepath.Join") or
     contains(line, "path.Join") or
     contains(line, "/") or
     contains(line, "\\")) and
    (contains(line, "r.FormValue") or
     contains(line, "r.URL.Query") or
     contains(line, "r.PostFormValue") or
     contains(line, "r.Header.Get") or
     contains(line, "ctx.Value") or
     contains(line, "os.Args"))
    // And no path validation/sanitization
    not (contains(line, "filepath.Clean") or
         contains(line, "path.Clean") or
         contains(line, "strings.Contains") and contains(line, "..") or
         contains(line, "validation.") or
         contains(line, "validate.") or
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

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

_has_path_func(line) if contains(line, "filepath.Join")
_has_path_func(line) if contains(line, "path.Join")
_has_path_func(line) if contains(line, "/")
_has_path_func(line) if contains(line, "\\")

_has_user_input(line) if contains(line, "r.FormValue")
_has_user_input(line) if contains(line, "r.URL.Query")
_has_user_input(line) if contains(line, "r.PostFormValue")
_has_user_input(line) if contains(line, "r.Header.Get")
_has_user_input(line) if contains(line, "ctx.Value")
_has_user_input(line) if contains(line, "os.Args")

_has_validation(line) if contains(line, "filepath.Clean")
_has_validation(line) if contains(line, "path.Clean")
_has_validation(line) if contains(line, "validation.")
_has_validation(line) if contains(line, "validate.")
_has_validation(line) if contains(line, "sanitize.")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for path construction with user input
    _has_path_func(line)
    _has_user_input(line)
    # And no path validation/sanitization
    not _has_validation(line)
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

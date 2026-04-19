package vulnetix.rules.vnx_go_038

import rego.v1

metadata := {
    "id": "VNX-GO-038",
    "name": "Potential mass assignment via struct binding",
    "description": "Binding user input directly to struct fields without validation can lead to mass assignment attacks where unauthorized fields are modified.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-038/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [915],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["mass-assignment", "struct", "binding"],
}

_is_go(path) if endswith(path, ".go")

_has_binding(line) if contains(line, "Bind")
_has_binding(line) if contains(line, "ShouldBind")
_has_binding(line) if contains(line, "Decode")
_has_binding(line) if contains(line, "Unmarshal")

_has_input_source(line) if contains(line, "r.Body")
_has_input_source(line) if contains(line, "r.Form")
_has_input_source(line) if contains(line, "r.PostForm")
_has_input_source(line) if contains(line, "ctx")
_has_input_source(line) if contains(line, "json.NewDecoder")

_has_validation(line) if contains(line, "binding:\"-\"")
_has_validation(line) if contains(line, "json:\"-\"")
_has_validation(line) if contains(line, "form:\"-\"")
_has_validation(line) if contains(line, "validate:\"-\"")
_has_validation(line) if contains(line, "validation.")
_has_validation(line) if contains(line, "validate.")
_has_validation(line) if contains(line, "structtag")
_has_validation(line) if contains(line, "selector")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    _has_binding(line)
    _has_input_source(line)
    not _has_validation(line)
    finding := {
        "rule_id": metadata.id,
        "message": "Struct binding from user input without field restrictions may lead to mass assignment; consider using struct tags or validation to limit allowed fields",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
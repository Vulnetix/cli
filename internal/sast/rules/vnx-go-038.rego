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

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for struct binding from request data
    (contains(line, "Bind") ;
     contains(line, "ShouldBind") ;
     contains(line, "Decode") ;
     contains(line, "Unmarshal")) and
    (contains(line, "r.Body") ;
     contains(line, "r.Form") ;
     contains(line, "r.PostForm") ;
     contains(line, "ctx") ;
     contains(line, "json.NewDecoder")) and
    # Check if there's no field validation or struct tags limiting fields
    not (contains(line, "binding:\"-\"") ;
         contains(line, "json:\"-\"") ;
         contains(line, "form:\"-\"") ;
         contains(line, "validate:\"-\"") ;
         contains(line, "validation.") ;
         contains(line, "validate.") ;
         contains(line, "structtag") ;
         contains(line, "selector"))
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
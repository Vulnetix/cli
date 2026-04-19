package vulnetix.rules.vnx_go_026

import rego.v1

metadata := {
    "id": "VNX-GO-026",
    "name": "Missing file type validation on upload",
    "description": "Accepting file uploads without validating the file type can lead to malicious file upload vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-026/",
    "languages": ["go"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [434],
    "capec": ["CAPEC-177"],
    "attack_technique": ["T1105"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["file-upload", "validation", "mime-type"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for multipart form handling or file upload handling
    (contains(line, "r.MultipartForm") or
     contains(line, "FormFile") or
     contains(line, "ParseMultipartForm") or
     contains(line, "UploadedFile")) and
    // Check if there's no file type validation nearby (simple heuristic)
    not (contains(line, "http.DetectContentType") or
         contains(line, "mime.") or
         contains(line, "filepath.Ext") or
         contains(line, "strings.HasSuffix") or
         contains(line, "strings.HasPrefix") or
         contains(line, "validation.") or
         contains(line, "validate."))
    finding := {
        "rule_id": metadata.id,
        "message": "File upload detected without apparent file type validation; consider validating MIME type or file extension",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
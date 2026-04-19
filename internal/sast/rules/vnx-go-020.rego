package vulnetix.rules.vnx_go_020

import rego.v1

metadata := {
    "id": "VNX-GO-020",
    "name": "Use of template.HTML with potential user input",
    "description": "Using template.HTML to mark user input as safe can lead to Cross-Site Scripting (XSS) vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-020/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [79],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["xss", "template", "html"],
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    endswith(path, ".go")
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    contains(line, "template.HTML")
    finding := {
        "rule_id": metadata.id,
        "message": "Use of template.HTML may lead to XSS if the input is not trusted",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
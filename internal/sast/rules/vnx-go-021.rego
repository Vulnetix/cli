package vulnetix.rules.vnx_go_021

import rego.v1

metadata := {
    "id": "VNX-GO-021",
    "name": "Potential XSS via fmt.Fprintf with HTML tags",
    "description": "Using fmt.Fprintf to output HTML tags combined with variables can lead to Cross-Site Scripting (XSS) if the variables contain user-controlled data.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-021/",
    "languages": ["go"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [79],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["xss", "html", "fmt"],
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    endswith(path, ".go")
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    contains(line, "fmt.Fprintf")
    contains(line, "<")
    contains(line, ">")
    finding := {
        "rule_id": metadata.id,
        "message": "Potential XSS via fmt.Fprintf with HTML tags and user input",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
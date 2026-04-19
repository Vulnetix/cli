package vulnetix.rules.vnx_html_001

import rego.v1

metadata := {
    "id": "VNX-HTML-001",
    "name": "Use of Jinja2 |safe filter",
    "description": "The |safe filter in Jinja2 templates can lead to Cross-Site Scripting (XSS) if the variable contains user-controlled data.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-html-001/",
    "languages": ["html"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [79],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1059.007"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["xss", "template", "jinja2", "safe"],
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    (endswith(path, ".html") || endswith(path, ".htm") || endswith(path, ".jinja") || endswith(path, ".jinja2"))
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    contains(line, "|safe")
    finding := {
        "rule_id": metadata.id,
        "message": "Use of |safe filter in template may lead to XSS if the value is not trusted",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
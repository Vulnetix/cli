package vulnetix.rules.vnx_go_022

import rego.v1

metadata := {
    "id": "VNX-GO-022",
    "name": "Use of eval() or dynamic code execution",
    "description": "Using eval() or similar dynamic code execution functions with user input can lead to Remote Code Execution (RCE) vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-022/",
    "languages": ["go"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [94],
    "capec": ["CAPEC-64"],
    "attack_technique": ["T1059.001"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["rce", "eval", "dynamic-code-execution"],
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    endswith(path, ".go")
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    (contains(line, "eval(") || contains(line, "template.Execute") || contains(line, "html/template.Execute"))
    and not contains(line, "//nolint")
    finding := {
        "rule_id": metadata.id,
        "message": "Use of eval() or dynamic code execution may lead to RCE if user input is not properly sanitized",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
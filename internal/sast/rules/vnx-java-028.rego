package vulnetix.rules.vnx_java_028

import rego.v1

metadata := {
    "id": "VNX-JAVA-028",
    "name": "SQL injection via string concatenation in Java",
    "description": "Constructing SQL queries by concatenating user input can lead to SQL injection vulnerabilities.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-028/",
    "languages": ["java"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [89],
    "capec": ["CAPEC-66"],
    "attack_technique": ["T1059.003"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["sql-injection", "database", "query"],
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    endswith(path, ".java")
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for string concatenation with SQL keywords
    (contains(line, ".execute(") ;
     contains(line, ".executeQuery(") ;
     contains(line, ".executeUpdate(")) and
    (contains(line, "+") ;
     contains(line, ".concat(") ;
     contains(line, "String.format("))
    finding := {
        "rule_id": metadata.id,
        "message": "Potential SQL injection via string concatenation; use parameterized queries instead",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
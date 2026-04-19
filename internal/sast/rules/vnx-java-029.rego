package vulnetix.rules.vnx_java_029

import rego.v1

metadata := {
    "id": "VNX-JAVA-029",
    "name": "XML External Entity (XXE) via DocumentBuilderFactory",
    "description": "Using DocumentBuilderFactory without disabling external entity processing can lead to XXE attacks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-029/",
    "languages": ["java"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [611],
    "capec": ["CAPEC-183"],
    "attack_technique": ["T1195.002"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["xxe", "xml", "parsing"],
}

findings contains finding if {
    some path in object.keys(input.file_contents)
    endswith(path, ".java")
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    // Look for DocumentBuilderFactory usage
    (contains(line, "DocumentBuilderFactory") or
     contains(line, "SAXParserFactory") or
     contains(line, "XMLReader")) and
    // Check if there's no call to setFeature for external entities
    not (contains(line, "setFeature") and
         (contains(line, "http://apache.org/xml/features/disallow-doctype-decl") or
          contains(line, "http://xml.org/sax/features/external-general-entities") or
          contains(line, "http://xml.org/sax/features/external-parameter-entities") or
          contains(line, "http://javax.xml.XMLConstants/feature/secure-processing")))
    finding := {
        "rule_id": metadata.id,
        "message": "XML factory used without disabling external entity processing; consider setting secure features to prevent XXE",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
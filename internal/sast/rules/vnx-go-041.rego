package vulnetix.rules.vnx_go_041

import rego.v1

metadata := {
    "id": "VNX-GO-041",
    "name": "Use of deprecated TLS version",
    "description": "Using deprecated TLS versions (TLS 1.0 or TLS 1.1) is insecure and should be avoided.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-041/",
    "languages": ["go"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [326],
    "capec": ["CAPEC-63"],
    "attack_technique": ["T1068.003"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["tls", "crypto", "version"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for TLS configuration that sets min or max version to TLS 1.0 or 1.1
    (contains(line, "tls.VersionTLS10") ;
     contains(line, "tls.VersionTLS11") ;
     contains(line, "TLS_RSA_WITH_") or // example of weak cipher suite, but we focus on version
     contains(line, "tls.TLS10") ;
     contains(line, "tls.TLS11")) and
    # Check if it's being used to set the version (like in tls.Config)
    (contains(line, "MinVersion") ;
     contains(line, "MaxVersion") ;
     contains(line, "Version"))
    finding := {
        "rule_id": metadata.id,
        "message": "Deprecated TLS version (TLS 1.0 or 1.1) detected; use TLS 1.2 or 1.3 instead",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
package vulnetix.rules.vnx_go_036

import rego.v1

metadata := {
    "id": "VNX-GO-036",
    "name": "Use of ECB block mode",
    "description": "Using ECB (Electronic Codebook) block mode is insecure and should not be used for cryptographic operations.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-036/",
    "languages": ["go"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [321],
    "capec": ["CAPEC-32"],
    "attack_technique": ["T1068.003"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["cryptography", "ecb", "block-mode", "weak-crypto"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for ECB mode usage
    (contains(line, "ECB") ;
     contains(line, "aes.NewCipher") and contains(line, "ECB") ;
     contains(line, "des.NewTripleDESCipher") and contains(line, "ECB") ;
     contains(line, "cipher.NewCTR") and contains(line, "ECB")) and
    not contains(line, "//nolint")
    finding := {
        "rule_id": metadata.id,
        "message": "Use of ECB block mode detected; use a secure mode like GCM, CBC, or CTR instead",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
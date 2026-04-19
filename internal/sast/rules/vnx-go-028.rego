package vulnetix.rules.vnx_go_028

import rego.v1

metadata := {
    "id": "VNX-GO-028",
    "name": "Use of weak cryptographic hash for password hashing",
    "description": "Using weak cryptographic hash functions like MD5 or SHA1 for password hashing is insecure and can lead to password compromise.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-028/",
    "languages": ["go"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [327],
    "capec": ["CAPEC-32"],
    "attack_technique": ["T1068.003"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["cryptography", "password", "hash", "weak-crypto"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
    some path in object.keys(input.file_contents)
    _is_go(path)
    lines := split(input.file_contents[path], "\n")
    some i, line in lines
    # Look for weak hash functions being used
    (contains(line, "md5.New") ;
     contains(line, "sha1.New") ;
     contains(line, "md5.Sum") ;
     contains(line, "sha1.Sum") ;
     contains(line, "crypto/md5") ;
     contains(line, "crypto/sha1")) and
    # Check if it's being used for password hashing (context clue)
    (contains(line, "Password") ;
     contains(line, "password") ;
     contains(line, "Passwd") ;
     contains(line, "passwd"))
    finding := {
        "rule_id": metadata.id,
        "message": "Weak cryptographic hash (MD5/SHA1) used for password hashing; use bcrypt, scrypt, or Argon2 instead",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
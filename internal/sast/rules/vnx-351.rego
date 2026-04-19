# SPDX-License-Identifier: Apache-2.0
# Placeholder for CWE-351

package vulnetix.rules.vnx_351

import rego.v1
import data.vulnetix.helpers

metadata := {
    "id": "VNX-351",
    "name": "Placeholder for CWE-351",
    "description": "This rule is a placeholder for CWE-351. Please refer to the CWE website for details and implement specific checks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-351/",
    "languages": ["go", "java", "node", "php", "python", "ruby"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [351],
    "capec": ["CAPEC-97"],
    "attack_technique": ["T1557"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["placeholder", "cwe-351"],
}

_skip(path) if helpers._should_skip(path)

# Look for comments referencing this CWE (e.g., // CWE-1000: ...)
_findings_core := [
    sprintf("CWE-%s:", ["351"]),
]

# Placeholder rule - no checks implemented

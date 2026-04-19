# SPDX-License-Identifier: Apache-2.0
# Placeholder for CWE-561

package vulnetix.rules.vnx_561

import rego.v1
import data.vulnetix.helpers

metadata := {
    "id": "VNX-561",
    "name": "Placeholder for CWE-561",
    "description": "This rule is a placeholder for CWE-561. Please refer to the CWE website for details and implement specific checks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-561/",
    "languages": ["go", "java", "node", "php", "python", "ruby"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [561],
    "capec": ["CAPEC-97"],
    "attack_technique": ["T1557"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["placeholder", "cwe-561"],
}

_skip(path) if helpers._should_skip(path)

# Look for comments referencing this CWE (e.g., // CWE-1000: ...)
_findings_core := [
    sprintf("CWE-%s:", ["561"]),
]

# Placeholder rule - no checks implemented

# SPDX-License-Identifier: Apache-2.0
# Placeholder for CWE-665

package vulnetix.rules.vnx_665

import rego.v1
import data.vulnetix.helpers

metadata := {
    "id": "VNX-665",
    "name": "Placeholder for CWE-665",
    "description": "This rule is a placeholder for CWE-665. Please refer to the CWE website for details and implement specific checks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-665/",
    "languages": ["go", "java", "node", "php", "python", "ruby"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [665],
    "capec": ["CAPEC-97"],
    "attack_technique": ["T1557"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["placeholder", "cwe-665"],
}

_skip(path) if helpers._should_skip(path)

# Look for comments referencing this CWE (e.g., // CWE-1000: ...)
_findings_core := [
    sprintf("CWE-%s:", ["665"]),
]

# Placeholder rule - no checks implemented

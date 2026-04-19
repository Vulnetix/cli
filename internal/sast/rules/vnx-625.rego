# SPDX-License-Identifier: Apache-2.0
# Placeholder for CWE-625

package vulnetix.rules.vnx_625

import rego.v1
import data.vulnetix.helpers

metadata := {
    "id": "VNX-625",
    "name": "Placeholder for CWE-625",
    "description": "This rule is a placeholder for CWE-625. Please refer to the CWE website for details and implement specific checks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-625/",
    "languages": ["go", "java", "node", "php", "python", "ruby"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [625],
    "capec": ["CAPEC-97"],
    "attack_technique": ["T1557"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["placeholder", "cwe-625"],
}

_skip(path) if helpers._should_skip(path)

# Look for comments referencing this CWE (e.g., // CWE-1000: ...)
_findings_core := [
    sprintf("CWE-%s:", ["625"]),
]

# Placeholder rule - no checks implemented

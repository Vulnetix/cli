# SPDX-License-Identifier: Apache-2.0
# Placeholder for CWE-695

package vulnetix.rules.vnx_695

import rego.v1
import data.vulnetix.helpers

metadata := {
    "id": "VNX-695",
    "name": "Placeholder for CWE-695",
    "description": "This rule is a placeholder for CWE-695. Please refer to the CWE website for details and implement specific checks.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-695/",
    "languages": ["go", "java", "node", "php", "python", "ruby"],
    "severity": "medium",
    "level": "warning",
    "kind": "sast",
    "cwe": [695],
    "capec": ["CAPEC-97"],
    "attack_technique": ["T1557"],
    "cvssv4": "",
    "cwss": "",
    "tags": ["placeholder", "cwe-695"],
}

_skip(path) if helpers._should_skip(path)

# Look for comments referencing this CWE (e.g., // CWE-1000: ...)
_findings_core := [
    sprintf("CWE-%s:", ["695"]),
]

# Placeholder rule - no checks implemented

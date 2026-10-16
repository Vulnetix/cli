# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_913

import rego.v1

metadata := {
	"id": "VNX-913",
	"name": "Request data evaluated as code (improper control of dynamically-managed code resources)",
	"description": "HTTP request data becoming code the process runs (CWE-913) is reported by VNX-94, which this rule used to duplicate line for line: Python eval()/exec()/compile() and JavaScript/TypeScript eval(), new Function()/Function(), vm.runInNewContext/runInThisContext/runInContext/compileFunction and new vm.Script given Flask/Django/DRF or Express/Koa request data, directly or through a variable assigned or destructured from it. VNX-94 reports every line this rule did, in more languages, with allowlist guards and numeric conversions honoured and at its correct (critical) severity, so this rule reports nothing and keeps its id only so that existing suppressions and policy references stay valid. Other CWE-913 shapes have their own rules: request-chosen modules (VNX-1027), unsafe reflection (VNX-470) and mass assignment (VNX-915).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-913/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [913],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["dynamic-code", "code-injection", "cwe-913"],
}

# Every request-to-evaluator line this rule matched is a VNX-94 finding (the
# same sinks, a superset of the sources, the same one- and two-hop flows), so
# reporting it here showed one problem twice. The cases under
# testdata/efficacy/vnx-913 now prove the rule stays quiet on those shapes;
# the same code is a true-positive case of VNX-94 (tp-from-913-*).
findings := set()

package vulnetix.rules.vnx_node_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-004",
	"name": "Express app without helmet",
	"description": "An Express application object is created (const app = express(), module.exports = express(), export const app = express()) in a file that imports express, and nothing in the same npm package (the files under the nearest directory holding a package.json, or the whole project when there is none) applies security headers: no helmet(...) call in code, no lusca, and no middleware that sets Content-Security-Policy, X-Frame-Options, Strict-Transport-Security or X-Content-Type-Options itself (setHeader/set/header by name, or as a key of a headers object). A helmet named only inside a string literal or a comment does not count. The app then serves without clickjacking, MIME-sniffing, HSTS or CSP protection. Reported once per file, on the first express() call. Not reported: express.Router() and other express.* factories, a helmet() call in any other module of the package, a helmet mentioned only in a comment (this still reports), test, example, sample, demo and benchmark code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-004/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [693],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["express", "config", "security-headers"],
}

_is_js(path) if regex.match(`\.(?:js|ts|mjs|cjs|mts|cts)$`, path)

_express_import := `require\(\s*['"]express['"]\s*\)|from\s+['"]express['"]`

_app_re := `(?:=|\(|return|export\s+default)\s*(?:express|require\(\s*['"]express['"]\s*\))\s*\(\s*\)`

# A code line (not a comment) that applies security headers.
_code_prefix := `(?m)^\s*(?:[^\s/*](?:[^/\n]|/[^/\n])*)?`

_headers := `['"](?i:content-security-policy|x-frame-options|strict-transport-security|x-content-type-options)['"]`

# Matched on the content with string literals removed, so "enable helmet()"
# in a log message is not a mitigation.
_call_mitigation_re := concat("", [_code_prefix, `(?:\bhelmet(?:\.\w+)?\s*\(|\blusca\b)`])

# Matched on the content with its literals kept: these name a module or a
# header in one. A header set by name, or as a key of a headers object.
_literal_mitigation_re := concat("", [
	_code_prefix,
	`(?:require\(\s*['"]helmet['"]\s*\)\s*\(|(?:setHeader|\.set|\.header)\s*\(\s*`, _headers, `|`, _headers, `\s*:)`,
])

_strip_strings(c) := regex.replace(c, `'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|\x60(?:[^\x60\\]|\\.)*\x60`, `""`)

# Block comments are removed first: a helmet setup commented out with /* */
# protects nothing.
_package_mitigated(root) if {
	some p, c in input.file_contents
	startswith(p, root)
	_is_js(p)
	regex.match(`(?i)helmet|lusca|x-frame-options|content-security-policy|strict-transport-security|x-content-type-options`, c)
	_mitigates(regex.replace(c, `(?s)/\*.*?\*/`, ""))
}

_mitigates(c) if regex.match(_literal_mitigation_re, c)

_mitigates(c) if regex.match(_call_mitigation_re, _strip_strings(c))

_skipped(path) if helpers.is_test_path(path)

_skipped(path) if regex.match(`(^|/)(examples?|samples?|demos?|benchmarks?|benches)/`, path)

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".d.ts")
	contains(content, "express")
	regex.match(_express_import, content)
	not _skipped(path)
	regex.match(concat("", [`(?m)`, _app_re]), content)
	lines := split(content, "\n")
	hits := [i |
		some i, line in lines
		contains(line, "express")
		not helpers.is_comment_line(line)
		regex.match(_app_re, line)
		not regex.match(`['"\x60][^'"\x60]*express\s*\(`, line)
	]
	count(hits) > 0
	root := _package_root(path)
	not _package_mitigated(root)
	i := hits[0]
	finding := {
		"rule_id": metadata.id,
		"message": "Express app created without helmet() or equivalent security-header middleware anywhere in this package; add app.use(helmet())",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

_dirs(path) := [concat("/", array.slice(parts, 0, k)) |
	parts := split(path, "/")
	count(parts) > 1
	some k in numbers.range(1, count(parts) - 1)
]

# The nearest ancestor directory holding a package.json ("" for the project
# root, or when there is none at all).
_package_root(path) := root if {
	cands := [d | some d in _dirs(path); input.file_set[concat("/", [d, "package.json"])]]
	count(cands) > 0
	root := concat("", [cands[count(cands) - 1], "/"])
}

_package_root(path) := "" if {
	not _has_package_dir(path)
}

_has_package_dir(path) if {
	some d in _dirs(path)
	input.file_set[concat("/", [d, "package.json"])]
}

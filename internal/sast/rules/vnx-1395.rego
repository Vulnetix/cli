# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1395

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1395",
	"name": "Dependency on a third-party component release with a well-known vulnerability",
	"description": "CWE-1395 (Dependency on Vulnerable Third-Party Component) is fully answered by dependency scanning (vulnetix sca), which matches every component against the vulnerability database. This rule is the offline floor: it reports the handful of JavaScript and Python components whose vulnerable releases are exploited in the wild, when a manifest, lockfile or page pins one. npm (package.json dependency entries pinned exactly, =X, or bounded <X / <=X below the fix; package-lock.json / npm-shrinkwrap.json entries by their \"version\", yarn.lock v1 and Berry entries by their version line):lodash before 4.17.21 (CVE-2021-23337, CVE-2020-8203), minimist before 0.2.4 / 1.2.6 (CVE-2021-44906), jsonwebtoken before 9.0.0 (CVE-2022-23529, CVE-2015-9235), handlebars before 4.7.7 (CVE-2021-23369), jquery before 3.5.0 (CVE-2020-11022), the compromised releases event-stream 3.3.6, ua-parser-js 0.7.29/0.8.0/1.0.0 and node-ipc 10.1.1-10.1.3, and any version of vm2 (sandbox escapes, discontinued) and node-serialize (CVE-2017-5941, no fix). Python (requirements*.txt, Pipfile, pyproject.toml, setup.py/setup.cfg pins ==X, <=X or <X): PyYAML before 5.4 (CVE-2020-14343) and Jinja2 before 2.10.1 (CVE-2019-10906). Pages and templates (script src / href): jQuery before 3.5.0, AngularJS 1.x (end of life with unfixed CVEs) and Bootstrap JavaScript 3.x before 3.4.1 and 4.x before 4.3.1 (CVE-2019-8331), from a CDN path or a versioned file name. Not reported: fixed releases, caret/tilde/>= ranges that admit a fixed release (the lockfile decides), lookalike packages (lodash.merge, @types/lodash, types-PyYAML, jquery-ui, jquery-migrate), stylesheets, versions in scripts or descriptions, manifests under node_modules or test/fixture paths, and comments. Java components are VNX-937 and unmaintained components VNX-1104. The engine evaluates this rule only when the scanned tree holds a file it recognises as JavaScript, Python or HTML (a lone requirements-dev.txt does not count; requirements.txt, Pipfile and package manifests do).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1395/",
	"languages": ["node", "python", "html"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1395],
	"capec": [],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["dependency-on-vulnerable-third-party-component", "sca", "cwe-1395"],
}

# ── Versions ───────────────────────────────────────────────────────────────

_ver(s) := v if {
	parts := split(s, ".")
	nums := [to_number(p) | some p in parts; regex.match(`^[0-9]+$`, p)]
	count(nums) == count(parts)
	v := array.slice(array.concat(nums, [0, 0, 0]), 0, 3)
}

_lt(a, b) if a[0] < b[0]

_lt(a, b) if {
	a[0] == b[0]
	a[1] < b[1]
}

_lt(a, b) if {
	a[0] == b[0]
	a[1] == b[1]
	a[2] < b[2]
}

_le(a, b) if _lt(a, b)

_le(a, a)

# Packages whose every release below one fix is vulnerable: name -> [fix, advisory].
_fix := {
	"lodash": [[4, 17, 21], "CVE-2021-23337"],
	"jsonwebtoken": [[9, 0, 0], "CVE-2022-23529"],
	"handlebars": [[4, 7, 7], "CVE-2021-23369"],
	"jquery": [[3, 5, 0], "CVE-2020-11022"],
	"pyyaml": [[5, 4, 0], "CVE-2020-14343"],
	"jinja2": [[2, 10, 1], "CVE-2019-10906"],
}

# Exact releases that were compromised.
_bad_release := {
	"event-stream": {"3.3.6"},
	"flatmap-stream": {"0.1.1"},
	"ua-parser-js": {"0.7.29", "0.8.0", "1.0.0"},
	"node-ipc": {"10.1.1", "10.1.2", "10.1.3"},
}

# Every published release is vulnerable and none is fixed.
_never_fixed := {"vm2": "sandbox escape CVE-2023-37466, project discontinued", "node-serialize": "CVE-2017-5941, no fixed release"}

# The release named by an exact pin is vulnerable; returns the advisory.
_vuln(name, s) := adv if {
	e := _fix[name]
	_lt(_ver(s), e[0])
	adv := e[1]
}

_vuln("minimist", s) := "CVE-2021-44906" if _lt(_ver(s), [0, 2, 4])

_vuln("minimist", s) := "CVE-2021-44906" if {
	v := _ver(s)
	v[0] == 1
	_lt(v, [1, 2, 6])
}

_vuln(name, s) := "compromised release" if s in _bad_release[name]

_vuln(name, _) := _never_fixed[name]

# Every release a bounded range admits is vulnerable.
_range_vuln(name, "<", s) := adv if {
	e := _fix[name]
	_le(_ver(s), e[0])
	adv := e[1]
}

_range_vuln(name, "<=", s) := adv if {
	e := _fix[name]
	_lt(_ver(s), e[0])
	adv := e[1]
}

_range_vuln(name, _, _) := _never_fixed[name]

# ── Files ──────────────────────────────────────────────────────────────────

_skip(path) if regex.match(`(?:^|/)(?:node_modules|bower_components|vendor)/`, path)

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(?i)(?:^|/)docs?/`, path)

_npm_names_re := `"(lodash|jsonwebtoken|handlebars|jquery|minimist|event-stream|flatmap-stream|ua-parser-js|node-ipc|vm2|node-serialize)"`

# Lockfile keys may carry a node_modules/ path before the name.
_lock_names_re := `"(?:[^"]*/)?(lodash|jsonwebtoken|handlebars|jquery|minimist|event-stream|flatmap-stream|ua-parser-js|node-ipc|vm2|node-serialize)"`

_msg(name, spec, adv) := sprintf("Dependency %s %s is a release with a well-known vulnerability (%s). Upgrade to a fixed release (or replace a component that has none) and run vulnetix sca for the full picture", [name, spec, adv])

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── package.json ───────────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	regex.match(`(?:^|/)package\.json$`, path)
	not _skip(path)
	regex.match(_npm_names_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "\"")
	some m in regex.find_all_string_submatch_n(`^\s*"(lodash|jsonwebtoken|handlebars|jquery|minimist|event-stream|flatmap-stream|ua-parser-js|node-ipc|vm2|node-serialize)"\s*:\s*"([^"]*)"`, line, 1)
	not _in_scripts(lines, i)
	adv := _npm_spec_vuln(m[1], trim_space(m[2]))
	f := _finding(path, i, line, _msg(m[1], m[2], adv))
}

_npm_spec_vuln(name, spec) := adv if {
	mm := regex.find_all_string_submatch_n(`^=?\s*v?([0-9]+(?:\.[0-9]+){0,2})$`, spec, 1)
	count(mm) > 0
	adv := _vuln(name, mm[0][1])
}

_npm_spec_vuln(name, spec) := adv if {
	mm := regex.find_all_string_submatch_n(`(?:^|\s)(<=?)\s*v?([0-9]+(?:\.[0-9]+){0,2})$`, spec, 1)
	count(mm) > 0
	not regex.match(`\|\|`, spec)
	adv := _range_vuln(name, mm[0][1], mm[0][2])
}

_npm_spec_vuln(name, spec) := adv if {
	not regex.match(`^=?\s*v?[0-9]+(?:\.[0-9]+){0,2}$`, spec)
	not regex.match(`(?:^|\s)<=?\s*v?[0-9]`, spec)
	adv := _never_fixed[name]
}

# The entry sits in "scripts" (a script named like a package is not a dependency).
_in_scripts(lines, i) if {
	opens := [j | some j in numbers.range(max([0, i - 200]), i); regex.match(`^\s*"[\w-]+"\s*:\s*\{`, lines[j])]
	count(opens) > 0
	regex.match(`^\s*"scripts"\s*:`, lines[max(opens)])
}

# ── package-lock.json / npm-shrinkwrap.json ────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	regex.match(`(?:^|/)(?:package-lock|npm-shrinkwrap)\.json$`, path)
	not _skip(path)
	regex.match(_lock_names_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "{")
	some m in regex.find_all_string_submatch_n(`^\s*"(?:(?:[^"]*/)?node_modules/)?(lodash|jsonwebtoken|handlebars|jquery|minimist|event-stream|flatmap-stream|ua-parser-js|node-ipc|vm2|node-serialize)"\s*:\s*\{\s*$`, line, 1)
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	vm := regex.find_all_string_submatch_n(`^\s*"version"\s*:\s*"v?([0-9]+(?:\.[0-9]+){0,2})"`, lines[j], 1)
	count(vm) > 0
	not _closed_before(lines, i, j)
	adv := _vuln(m[1], vm[0][1])
	f := _finding(path, i, line, _msg(m[1], vm[0][1], adv))
}

_closed_before(lines, i, j) if {
	i + 1 <= j - 1
	some k in helpers.span(i + 1, j - 1)
	regex.match(`^\s*\}`, lines[k])
}

# ── Python manifests ───────────────────────────────────────────────────────

_py_manifest(path) if regex.match(`(?i)(?:^|/)(?:[^/]*requirements[^/]*\.(?:txt|in)|pipfile|pyproject\.toml|setup\.py|setup\.cfg)$`, path)

findings contains f if {
	some path, content in input.file_contents
	_py_manifest(path)
	not _skip(path)
	regex.match(`(?i)pyyaml|jinja2`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pyyaml|jinja2`, line)
	not helpers.is_comment_line(line)
	some h in _py_hits(line)
	f := _finding(path, i, line, _msg(h[0], h[1], h[2]))
}

# PyYAML==5.1 / "PyYAML<5.4" / jinja2<=2.10 (a name boundary on both sides).
_py_hits(line) := _py_pins(line) | _py_toml(line)

_py_pins(line) := {[name, concat("", [m[2], m[3]]), adv] |
	some m in regex.find_all_string_submatch_n(`(?i)(?:^|[\s"',\[])(pyyaml|jinja2)\s*(===|==|<=|<)\s*([0-9]+(?:\.[0-9]+){0,2})\b`, line, -1)
	name := lower(m[1])
	adv := _py_spec_vuln(name, m[2], m[3])
}

# Pipfile / Poetry: pyyaml = "==5.3.1" or pyyaml = "5.3.1" (Poetry exact).
_py_toml(line) := {[name, m[3], adv] |
	some m in regex.find_all_string_submatch_n(`(?i)^\s*["']?(pyyaml|jinja2)["']?\s*=\s*["'](===|==|<=|<)?\s*([0-9]+(?:\.[0-9]+){0,2})["']`, line, 1)
	name := lower(m[1])
	adv := _py_spec_vuln(name, m[2], m[3])
}

_py_spec_vuln(name, op, v) := _vuln(name, v) if op in {"==", "===", ""}

_py_spec_vuln(name, op, v) := _range_vuln(name, op, v) if op in {"<", "<="}

# ── Pages and templates ────────────────────────────────────────────────────

_page_re := `(?i)\.(?:html?|xhtml|cshtml|vbhtml|razor|erb|ejs|php|phtml|jsp|jspx|twig|hbs|handlebars|mustache|vue|svelte|njk|gohtml|tmpl|tpl|j2|jinja2?|liquid|aspx|ascx|master)$`

# Inside a src= or href= value: <jquery file or CDN path with a version>.
_jquery_re := `(?i)(?:src|href)\s*=\s*["'][^"']*?jquery(?:[-.@]|/)v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:/|[.-](?:min|slim)|\.js)`

_angular_re := `(?i)(?:src|href)\s*=\s*["'][^"']*?angular(?:js|\.js)?(?:[-.@]|/)v?(1\.[0-9]+\.[0-9]+)(?:/|[.-]min|\.js)`

_bootstrap_re := `(?i)(?:src|href)\s*=\s*["'][^"']*?bootstrap(?:[-.@]|/)v?([0-9]+\.[0-9]+\.[0-9]+)[^"'\s>]*\.js["']`

findings contains f if {
	some path, content in input.file_contents
	regex.match(_page_re, path)
	not _skip(path)
	regex.match(`(?i)jquery|angular|bootstrap`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)(?:src|href)\s*=`, line)
	some h in _page_hits(line)
	f := _finding(path, i, line, _msg(h[0], h[1], h[2]))
}

_page_hits(line) := {["jquery", m[1], adv] |
	some m in regex.find_all_string_submatch_n(_jquery_re, line, -1)
	adv := _vuln("jquery", m[1])
} | {["angularjs", m[1], "AngularJS 1.x is end of life with unfixed CVEs (e.g. CVE-2022-25869)"] |
	some m in regex.find_all_string_submatch_n(_angular_re, line, -1)
} | {["bootstrap", m[1], "CVE-2019-8331"] |
	some m in regex.find_all_string_submatch_n(_bootstrap_re, line, -1)
	_bootstrap_vuln(_ver(m[1]))
}

_bootstrap_vuln(v) if v[0] < 3

_bootstrap_vuln(v) if {
	v[0] == 3
	_lt(v, [3, 4, 1])
}

_bootstrap_vuln(v) if {
	v[0] == 4
	_lt(v, [4, 3, 1])
}

# ── yarn.lock (v1 and Berry) ───────────────────────────────────────────────

# The version line of an entry whose header names the package:
#   lodash@^4.17.4, lodash@^4.17.5:      /  "lodash@npm:^4.17.4":
#     version "4.17.4"                   /    version: 4.17.4
findings contains f if {
	some path, content in input.file_contents
	regex.match(`(?:^|/)yarn\.lock$`, path)
	not _skip(path)
	regex.match(_yarn_names_re, content)
	lines := split(content, "\n")
	some i, line in lines
	startswith(line, "  version")
	vm := regex.find_all_string_submatch_n(`^  version:?\s+"?v?([0-9]+(?:\.[0-9]+){0,2})"?\s*$`, line, 1)
	count(vm) > 0
	some j in numbers.range(max([0, i - 3]), i - 1)
	hm := regex.find_all_string_submatch_n(`^"?(lodash|jsonwebtoken|handlebars|jquery|minimist|event-stream|flatmap-stream|ua-parser-js|node-ipc|vm2|node-serialize)@`, lines[j], 1)
	count(hm) > 0
	not _yarn_between(lines, j, i)
	adv := _vuln(hm[0][1], vm[0][1])
	f := _finding(path, i, line, _msg(hm[0][1], vm[0][1], adv))
}

_yarn_names_re := `(?m)^"?(?:lodash|jsonwebtoken|handlebars|jquery|minimist|event-stream|flatmap-stream|ua-parser-js|node-ipc|vm2|node-serialize)@`

# Another entry header (or a blank line) between the header and the version.
_yarn_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	not startswith(lines[k], " ")
}

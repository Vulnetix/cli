# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1104

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1104",
	"name": "Use of Unmaintained Third Party Components",
	"description": "A dependency manifest declares a third-party component whose maintainers have deprecated, archived or end-of-lifed it, so security fixes no longer arrive: npm request/request-promise(-native), node-uuid, jade, node-sass, tslint, gulp-util, coffee-script, istanbul, babel-eslint, nomnom, bower, phantomjs(-prebuilt), protractor, swig and the npm 'crypto' stub in package.json dependency blocks; pycrypto, nose, PyPDF2, MySQL-python, pep8, sklearn and distribute in requirements*.txt (and requirements/*.txt), pyproject.toml (PEP 621 arrays and Poetry dependency tables) and Pipfile package sections; paperclip, therubyracer and Ruby Sass (gem 'sass') in a Gemfile; and log4j 1.x (log4j:log4j), commons-httpclient 3.x and Jackson 1.x (org.codehaus.jackson) in pom.xml and Gradle builds. Reported: the declaring line, with the maintained successor in the message. Not reported: the successors themselves (uuid, pug, sass, eslint, nyc, pycryptodome, pypdf, nose2, scikit-learn, mysqlclient, kt-paperclip, log4j 2, httpclient 4), lookalike names (request-ip, sass-rails, log4j-api, log4j-1.2-api), the names used as npm script keys or descriptions, Poetry and Pipfile [scripts] entries, and commented-out entries (including entries inside XML comments in pom.xml). A component that is merely old, or unmaintained without an upstream announcement, is not inferred.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1104/",
	"languages": ["javascript", "python", "ruby", "java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1104],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["dependencies", "unmaintained", "supply-chain", "cwe-1104"],
}

_npm := {
	"request": "fetch, undici or axios",
	"request-promise": "fetch, undici or axios",
	"request-promise-native": "fetch, undici or axios",
	"node-uuid": "uuid",
	"jade": "pug",
	"node-sass": "sass (Dart Sass)",
	"tslint": "eslint with typescript-eslint",
	"gulp-util": "the individual packages it bundled",
	"coffee-script": "coffeescript",
	"istanbul": "nyc or c8",
	"babel-eslint": "@babel/eslint-parser",
	"nomnom": "commander or yargs",
	"bower": "npm or yarn",
	"phantomjs": "puppeteer or playwright",
	"phantomjs-prebuilt": "puppeteer or playwright",
	"protractor": "playwright, cypress or webdriverio",
	"swig": "nunjucks",
	"crypto": "the built-in node:crypto module",
}

_pypi := {
	"pycrypto": "pycryptodome",
	"nose": "pytest or nose2",
	"pypdf2": "pypdf",
	"mysql-python": "mysqlclient",
	"pep8": "pycodestyle",
	"sklearn": "scikit-learn",
	"distribute": "setuptools",
}

_gems := {
	"paperclip": "Active Storage or kt-paperclip",
	"therubyracer": "mini_racer",
	"sass": "sassc or dartsass-rails",
}

_maven := {
	"log4j:log4j": "log4j 2 (org.apache.logging.log4j) or logback",
	"commons-httpclient:commons-httpclient": "Apache HttpClient 4/5 (org.apache.httpcomponents)",
	"org.codehaus.jackson": "Jackson 2 (com.fasterxml.jackson)",
}

_emit(path, i, line, name, repl) := {
	"rule_id": metadata.id,
	"message": sprintf("Dependency '%s' is deprecated or end-of-life upstream and no longer receives security fixes; migrate to %s", [name, repl]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── npm ──────────────────────────────────────────────────────────────────
_npm_gate := `"(?:request|request-promise|request-promise-native|node-uuid|jade|node-sass|tslint|gulp-util|coffee-script|istanbul|babel-eslint|nomnom|bower|phantomjs|phantomjs-prebuilt|protractor|swig|crypto)"\s*:`

# The nearest object opened above line i is a dependency block (they are flat).
_in_dep_block(lines, i) if {
	openers := [j | some j in numbers.range(max([0, i - 400]), i - 1); regex.match(`:\s*\{\s*$`, lines[j])]
	count(openers) > 0
	regex.match(`"(?:dependencies|devDependencies|peerDependencies|optionalDependencies|bundledDependencies|resolutions|overrides)"\s*:\s*\{\s*$`, lines[max(openers)])
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(?:^|/)package\.json$`, path)
	regex.match(_npm_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`^\s*"([^"]+)"\s*:\s*"[^"]*"\s*,?\s*$`, line, 1)
	count(m) > 0
	repl := _npm[m[0][1]]
	_in_dep_block(lines, i)
	finding := _emit(path, i, line, m[0][1], repl)
}

# ── Python ───────────────────────────────────────────────────────────────
_py_names := `(pycrypto|nose|pypdf2|mysql[-_.]python|pep8|sklearn|distribute)`

_pep503(n) := regex.replace(lower(n), `[-_.]+`, "-")

_py_line_re(path) := concat("", [`(?i)^\s*`, _py_names, `\s*(?:[=<>!~;\[@ ]|$)`]) if regex.match(`(?:^|/)(?:requirements[^/]*|requirements/[^/]+)\.(?:txt|in)$`, path)

_py_line_re(path) := concat("", [`(?i)^\s*["']`, _py_names, `\s*(?:[=<>!~;\[@ ]|["'])`]) if regex.match(`(?:^|/)pyproject\.toml$`, path)

_py_line_re(path) := concat("", [`(?i)^\s*["']?`, _py_names, `["']?\s*=`]) if regex.match(`(?:^|/)Pipfile$`, path)

findings contains finding if {
	some path, content in input.file_contents
	re := _py_line_re(path)
	regex.match(concat("", [`(?im)^\s*["']?`, _py_names, `\b`]), content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	name := _pep503(m[0][1])
	repl := _pypi[name]
	_py_section_ok(path, lines, i)
	finding := _emit(path, i, line, m[0][1], repl)
}

# Poetry declares dependencies as TOML keys: name = "^1.2" or name = { ... }.
findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(?:^|/)pyproject\.toml$`, path)
	contains(content, "[tool.poetry")
	regex.match(concat("", [`(?im)^\s*`, _py_names, `\s*=`]), content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(concat("", [`(?i)^\s*`, _py_names, `\s*=\s*["'{]`]), line, 1)
	count(m) > 0
	repl := _pypi[_pep503(m[0][1])]
	regex.match(`^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.\]]+\.dependencies)$`, _toml_section(lines, i))
	finding := _emit(path, i, line, m[0][1], repl)
}

# The nearest TOML table header above line i ([packages], [[source]], ...).
_toml_section(lines, i) := s if {
	hs := [j | some j in numbers.range(max([0, i - 300]), i - 1); regex.match(`^\s*\[`, lines[j])]
	count(hs) > 0
	s := trim_space(regex.replace(lines[max(hs)], `^\s*\[+\s*|\s*\]+.*$`, ""))
}

_toml_section(lines, i) := "" if not _has_header_above(lines, i)

_has_header_above(lines, i) if {
	some j in numbers.range(max([0, i - 300]), i - 1)
	regex.match(`^\s*\[`, lines[j])
}

# A Pipfile key is a package only inside a package category, never under
# [scripts], [requires], [pipenv] or [[source]].
_py_section_ok(path, _, _) if not endswith(path, "Pipfile")

_py_section_ok(path, lines, i) if {
	endswith(path, "Pipfile")
	not _toml_section(lines, i) in {"scripts", "requires", "pipenv", "source", ""}
}

# ── Ruby ─────────────────────────────────────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(?:^|/)(?:Gemfile|gems\.rb)$`, path)
	regex.match(`(?m)^\s*gem\s+["'](?:paperclip|therubyracer|sass)["']`, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`^\s*gem\s+["']([\w-]+)["']`, line, 1)
	count(m) > 0
	repl := _gems[m[0][1]]
	finding := _emit(path, i, line, m[0][1], repl)
}

# ── Maven ────────────────────────────────────────────────────────────────
_xml_val(line, tag) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", [`<`, tag, `>\s*([\w.-]+)\s*</`, tag, `>`]), line, 1)
	count(m) > 0
}

# The line with any complete or trailing XML comment removed.
_xml_code(line) := regex.replace(regex.replace(line, `<!--.*?-->`, ""), `<!--.*$`, "")

# Line i sits inside a multi-line <!-- ... --> block opened above it.
_in_xml_comment(lines, i) if {
	some j in numbers.range(max([0, i - 60]), i - 1)
	regex.match(`<!--(?:[^-]|-[^-]|--[^>])*$`, lines[j])
	not _closed_between(lines, j, i)
}

_closed_between(lines, j, i) if {
	some k in helpers.span(j + 1, i - 1)
	contains(lines[k], "-->")
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(?:^|/)pom\.xml$`, path)
	regex.match(`<(?:artifactId|groupId)>\s*(?:log4j|commons-httpclient|org\.codehaus\.jackson)\s*<`, content)
	lines := split(content, "\n")
	some i, line in lines
	a := _xml_val(_xml_code(line), "artifactId")
	a in {"log4j", "commons-httpclient"}
	not _in_xml_comment(lines, i)
	some j in numbers.range(max([0, i - 4]), min([count(lines) - 1, i + 4]))
	_xml_val(_xml_code(lines[j]), "groupId") == a
	key := concat(":", [a, a])
	finding := _emit(path, i, line, key, _maven[key])
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(?:^|/)pom\.xml$`, path)
	contains(content, "org.codehaus.jackson")
	lines := split(content, "\n")
	some i, line in lines
	_xml_val(_xml_code(line), "groupId") == "org.codehaus.jackson"
	not _in_xml_comment(lines, i)
	finding := _emit(path, i, line, "org.codehaus.jackson", _maven["org.codehaus.jackson"])
}

# ── Gradle ───────────────────────────────────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.gradle(?:\.kts)?$`, path)
	regex.match(`["'](?:log4j:log4j|commons-httpclient:commons-httpclient|org\.codehaus\.jackson:)`, content)
	lines := split(content, "\n")
	some i, line in lines
	not regex.match(`^\s*(?://|/\*|\*)`, line)
	m := regex.find_all_string_submatch_n(`["'](log4j:log4j|commons-httpclient:commons-httpclient|org\.codehaus\.jackson)(?::|["'])`, line, 1)
	count(m) > 0
	finding := _emit(path, i, line, m[0][1], _maven[m[0][1]])
}

# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_548

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-548",
	"name": "Exposure of Information Through Directory Listing",
	"description": "A web server or framework is configured to answer a request for a directory with a listing of its files, so anyone can enumerate backups, logs, uploads and keys that were never linked. Reported: a serveIndex(...) call (the serve-index middleware) and @fastify/static registered with list: true in JavaScript/TypeScript; Django's static serve view given show_indexes: True or static(..., show_indexes=True), aiohttp add_static(..., show_index=True) and Flask-AutoIndex AutoIndex(app, ...) in Python; a Tomcat listings or Jetty dirAllowed DefaultServlet init-param set to true in web.xml, Jetty setDirectoriesListed(true) and setInitParameter(\"dirAllowed\", \"true\") in Java; nginx autoindex on (also inside a one-line location block); and Apache Options Indexes / +Indexes / All in httpd.conf, apache2.conf, site .conf files and .htaccess. Not reported: importing serve-index without calling it, express.static and other file servers that do not list directories, the settings when switched off (autoindex off, Options -Indexes, listings false, show_indexes False), commented-out directives, string literals and test files. Go's http.FileServer, which lists any directory without an index.html, is not reported because almost every use serves a directory of public assets on purpose.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-548/",
	"languages": ["node", "python", "java", "generic"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [548],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["directory-listing", "cwe-548"],
}

_base(path) := b if {
	parts := split(path, "/")
	b := lower(parts[count(parts) - 1])
}

_kind(path) := "js" if {
	some ext in {".js", ".ts", ".mjs", ".cjs"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_kind(path) := "py" if endswith(path, ".py")

_kind(path) := "java" if endswith(path, ".java")

_kind(path) := "webxml" if _base(path) == "web.xml"

_kind(path) := "nginx" if endswith(_base(path), ".conf")

_kind(path) := "nginx" if regex.match(`(^|/)sites-(available|enabled)/[^/.]+$`, path)

_kind(path) := "apache" if _base(path) == ".htaccess"

# Whole-file gate (a regular expression) and per-line gate, by file kind.
_needle := {
	"js": `serveIndex|fastify-static|@fastify/static`,
	"py": `ndex`,
	"java": `setDirectoriesListed|dirAllowed`,
	"webxml": `<param-name>\s*(listings|dirAllowed)\s*<`,
	"nginx": `ndex|Options`,
	"apache": `Indexes|Options`,
}

# The reported line of a web.xml is the param-value, not the param-name.
_line_needle := {
	"js": `serveIndex|list`,
	"py": `ndex`,
	"java": `setDirectoriesListed|dirAllowed`,
	"webxml": `true`,
	"nginx": `autoindex|Options`,
	"apache": `Options`,
}

# String literals blanked for code files.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_lists("js", _, _, line) if regex.match(`(^|[^\w.$])serveIndex\s*\(`, _code(line))

_lists("py", _, _, line) if regex.match(`['"]show_indexes['"]\s*:\s*True\b`, line)

_lists("py", _, _, line) if regex.match(`\.add_static\s*\(.*\bshow_index\s*=\s*True\b`, line)

# @fastify/static registered with `list: true` (or a list options object).
_lists("js", lines, i, line) if {
	regex.match(`^\s*list\s*:\s*(true\b|\{)`, line)
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(`\bregister\s*\(\s*(require\s*\(\s*['"](@fastify/static|fastify-static)['"]\s*\)|\w*[sS]tatic\w*)`, lines[j])
	not _closed_between(lines, j, i)
}

_closed_between(lines, j, i) if {
	some k in numbers.range(j + 1, i - 1)
	regex.match(`^\s*\}\s*\)`, lines[k])
}

_lists("py", _, _, line) if regex.match(`(^|[^\w.])AutoIndex\s*\(`, _code(line))

# django.conf.urls.static.static(..., show_indexes=True)
_lists("py", _, _, line) if regex.match(`\bstatic\s*\(.*\bshow_indexes\s*=\s*True\b`, line)

_lists("java", _, _, line) if regex.match(`\.setDirectoriesListed\s*\(\s*true\s*\)`, line)

# Jetty DefaultServlet init parameter set in code.
_lists("java", _, _, line) if regex.match(`\.setInitParameter\s*\(\s*"(org\.eclipse\.jetty\.servlet\.Default\.)?dirAllowed"\s*,\s*"true"\s*\)`, line)

# <param-value>true</param-value> right after <param-name>listings</param-name>
# (Tomcat) or <param-name>dirAllowed</param-name> (Jetty).
_lists("webxml", lines, i, line) if {
	regex.match(`<param-value>\s*true\s*</param-value>`, line)
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`<param-name>\s*(listings|dirAllowed)\s*</param-name>`, lines[j])
}

_lists("webxml", _, _, line) if regex.match(`<param-name>\s*(listings|dirAllowed)\s*</param-name>\s*<param-value>\s*true\s*</param-value>`, line)

# autoindex on; at the start of the line or after { or ; (a one-line block).
_lists("nginx", _, _, line) if regex.match(`^[^#]*?(?:^|[{;])\s*autoindex\s+on\s*;`, line)

# Apache `Options Indexes` / `Options +Indexes` / `Options All` (All
# includes Indexes), also in a .conf file.
_lists(kind, _, _, line) if {
	kind in {"nginx", "apache"}
	regex.match(`^\s*Options\s+([^#]*\s)?(\+?Indexes|\+?All)\b`, line)
}

findings contains finding if {
	some path, content in input.file_contents
	kind := _kind(path)
	regex.match(_needle[kind], content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_line_needle[kind], line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*<!--`, line)
	_lists(kind, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Directory listing is enabled: a request for a directory returns the names of every file in it, so unlinked backups, logs, uploads and keys can be found and downloaded. Turn listing off and serve only the files that are meant to be public",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

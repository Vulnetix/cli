# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_410

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-410",
	"name": "Insufficient Resource Pool",
	"description": "Reports a shared server resource pool capped at one or two members by a literal, so a handful of slow or deliberately held requests exhausts it and every other client waits. Java: HikariCP `setMaximumPoolSize(1|2)`, Commons DBCP/Pool `setMaxTotal`/`setMaxActive(1|2)`, Tomcat/Jetty connector `setMaxThreads(1|2)`, Jetty `new QueuedThreadPool(1|2)`, and, in a file that serves requests (ServerSocket.accept, HttpServlet, HttpHandler, @RestController/@Controller, @WebServlet), `Executors.newFixedThreadPool(1|2)` and `new ThreadPoolExecutor(core, 1|2, ...)`. Spring `.properties` files and `application*.yml`/`bootstrap*.yml` (key read under its `hikari:` / `dbcp2:` / `tomcat:` / `tomcat: threads:` parents): `*.hikari.maximum-pool-size`, `*.dbcp2.max-total`, `spring.datasource.tomcat.max-active`, `server.tomcat.threads.max` / `server.tomcat.max-threads` (in kebab, camel or snake case, as Spring binds them) set to 1 or 2. Not reported: sizes from variables or expressions, larger literals, scheduled/timer executors and newSingleThreadExecutor (a deliberate serialiser), a one-thread executor in code that does not serve requests, test files, comments and strings. Whether a larger literal suffices for peak load cannot be judged statically.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-410/",
	"languages": ["java", "generic"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [410],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["resource-pool", "cwe-410"],
}

_strip(l) := regex.replace(l, `"(\\.|[^"\\])*"`, `""`)

_report(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_msg := "This shared pool is capped at %s: a few slow or deliberately held requests take every member and all other clients block. Size the pool for peak concurrency (from configuration, not a literal of 1 or 2) and set an acquisition timeout."

# Pools that only exist to serve concurrent clients: report anywhere.
_server_pool_re := `(?:\.setMaximumPoolSize|\.setMaxTotal|\.setMaxActive|\.setMaxThreads)\(\s*([12])\s*\)|\bnew\s+QueuedThreadPool\(\s*([12])\s*[,)]`

# General executors: report only where requests are served.
_executor_re := `\bExecutors\.newFixedThreadPool\(\s*([12])\s*[,)]|\bnew\s+ThreadPoolExecutor\(\s*\d+\s*,\s*([12])\s*,`

_serves_requests(content) if regex.match(`\.accept\(\s*\)|extends\s+HttpServlet\b|implements\s+[\w,\s]*\bHttpHandler\b|@(RestController|Controller|WebServlet)\b`, content)

_size(m) := m[1] if m[1] != ""

_size(m) := m[2] if m[1] == ""

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`Max(imumPoolSize|Total|Active|Threads)\(|QueuedThreadPool\(|newFixedThreadPool\(|ThreadPoolExecutor\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Max(imumPoolSize|Total|Active|Threads)\(|QueuedThreadPool\(|newFixedThreadPool\(|ThreadPoolExecutor\(`, line)
	not helpers.is_comment_line(line)
	code := _strip(line)
	some m in _matches(content, code)
	finding := _report(path, i, line, sprintf(_msg, [_size(m)]))
}

_matches(content, code) := array.concat(regex.find_all_string_submatch_n(_server_pool_re, code, 1), _exec_matches(content, code))

_exec_matches(content, code) := regex.find_all_string_submatch_n(_executor_re, code, 1) if {
	_serves_requests(content)
} else := []

# Spring relaxed binding: kebab-case, camelCase and snake_case all bind.
_prop_key := `(?:[\w.-]*\.hikari\.(?i:maximum[-_]?pool[-_]?size)|server\.tomcat\.threads\.max|server\.tomcat\.(?i:max[-_]?threads)|[\w.-]*\.dbcp2\.(?i:max[-_]?total)|spring\.datasource\.tomcat\.(?i:max[-_]?active))`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".properties")
	not helpers.is_test_path(path)
	regex.match(concat("", [`(?m)^\s*`, _prop_key, `\s*[=:]\s*[12]\s*$`]), content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, _prop_key, `\s*[=:]\s*([12])\s*$`]), line, 1)
	count(m) > 0
	finding := _report(path, i, line, sprintf(_msg, [m[0][1]]))
}

# Spring Boot YAML: the key's meaning comes from its ancestors.
_spring_yaml(path) if regex.match(`(^|/)(application|bootstrap)[\w-]*\.ya?ml$`, path)

_yindent(l) := count(l) - count(trim_left(l, " "))

# The nearest line above i with a smaller indent: the key's parent.
_yparent(lines, i) := k if {
	ind := _yindent(lines[i])
	ks := [j |
		some j in numbers.range(max([0, i - 30]), i - 1)
		t := trim_space(lines[j])
		t != ""
		not startswith(t, "#")
		_yindent(lines[j]) < ind
	]
	count(ks) > 0
	k := max(ks)
}

_ykey(l) := trim_space(split(l, ":")[0])

_yaml_pool(lines, i, key) if {
	key in {"maximum-pool-size", "maximumPoolSize", "maximum_pool_size"}
	_ykey(lines[_yparent(lines, i)]) == "hikari"
}

_yaml_pool(lines, i, key) if {
	key in {"max-threads", "maxThreads"}
	_ykey(lines[_yparent(lines, i)]) == "tomcat"
}

_yaml_pool(lines, i, key) if {
	key in {"max-total", "maxTotal"}
	_ykey(lines[_yparent(lines, i)]) == "dbcp2"
}

_yaml_pool(lines, i, "max") if {
	p := _yparent(lines, i)
	_ykey(lines[p]) == "threads"
	_ykey(lines[_yparent(lines, p)]) == "tomcat"
}

findings contains finding if {
	some path, content in input.file_contents
	_spring_yaml(path)
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s+(maximum-pool-size|maximumPoolSize|maximum_pool_size|max-threads|maxThreads|max-total|maxTotal|max)\s*:\s*['"]?[12]['"]?\s*(#.*)?$`, content)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`^\s+(maximum-pool-size|maximumPoolSize|maximum_pool_size|max-threads|maxThreads|max-total|maxTotal|max)\s*:\s*['"]?([12])['"]?\s*(#.*)?$`, line, 1)
	count(m) > 0
	_yaml_pool(lines, i, m[0][1])
	finding := _report(path, i, line, sprintf(_msg, [m[0][2]]))
}

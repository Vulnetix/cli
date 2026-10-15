package vulnetix.rules.vnx_java_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-002",
	"name": "Spring actuator endpoints exposed",
	"description": "Reports Spring Boot configuration (application/bootstrap[-profile].properties|yml|yaml) that exposes sensitive actuator endpoints over HTTP: management.endpoints.web.exposure.include set to * or naming env, heapdump, threaddump, shutdown, jolokia, configprops, httptrace, logfile or restart (properties, flat YAML keys, nested and partly dotted YAML whose full key path is management.endpoints.web.exposure.include, inline and block YAML lists), management.endpoint.shutdown.enabled=true, and the Spring Boot 1.x switches management.security.enabled=false and endpoints.sensitive=false. These leak heap dumps, environment variables and credentials, or allow remote shutdown. Applies to Java and Kotlin projects. Not reported: an include of harmless endpoints (health, info, metrics, prometheus), exclude lists, JMX exposure, an include key under any other YAML mapping, commented lines, test resources, and projects whose Java or Kotlin code secures actuator endpoints with EndpointRequest (Spring Security).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-002/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["spring", "config", "actuator", "information-disclosure"],
}

_is_config(path) if regex.match(`(^|/)(application|bootstrap)(-[\w.-]+)?\.(properties|ya?ml)$`, path)

_sensitive := `(?i)(^|[\s,\["'])(\*|env|heapdump|threaddump|shutdown|jolokia|configprops|httptrace|logfile|restart)($|[\s,\]"'])`

# Actuator endpoints guarded by Spring Security somewhere in the project.
_secured if {
	some p, c in input.file_contents
	regex.match(`\.(java|kt)$`, p)
	contains(c, "EndpointRequest.to")
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

findings contains finding if {
	some path, content in input.file_contents
	_is_config(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)exposure|shutdown|management\.security|endpoints\.sensitive|security:|sensitive:`, content)
	not _secured
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	not startswith(trim_space(line), "!")
	_exposes(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Sensitive Spring Boot actuator endpoints are exposed over HTTP; expose only health and info, and protect the rest with Spring Security or a separate management port",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# management.endpoints.web.exposure.include=* (properties or flat YAML key)
_exposes(_, _, line) if {
	m := regex.find_all_string_submatch_n(`^\s*management\.endpoints\.web\.exposure\.include\s*[=:]\s*(.*)$`, line, 1)
	count(m) > 0
	regex.match(_sensitive, trim_space(m[0][1]))
}

# nested YAML: exposure:\n  include: "*"
_exposes(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`^\s+(([\w-]+\.)*include)\s*:\s*(.*)$`, line, 1)
	count(m) > 0
	_under_web_exposure(lines, i, m[0][1])
	_yaml_value_sensitive(lines, i, trim_space(m[0][3]))
}

_exposes(_, _, line) if regex.match(`^\s*management\.endpoint\.shutdown\.enabled\s*[=:]\s*["']?true`, line)

_exposes(lines, i, line) if {
	regex.match(`^\s+enabled\s*:\s*["']?true`, line)
	j := _parent(lines, i)
	regex.match(`^\s*shutdown\s*:\s*$`, lines[j])
	k := _parent(lines, j)
	regex.match(`^\s*endpoint\s*:\s*$`, lines[k])
}

# Spring Boot 1.x: actuator authentication switched off.
_exposes(_, _, line) if regex.match(`^\s*(management\.security\.enabled|endpoints\.sensitive)\s*[=:]\s*["']?false`, line)

_exposes(lines, i, line) if {
	regex.match(`^\s+enabled\s*:\s*["']?false`, line)
	j := _parent(lines, i)
	regex.match(`^\s*security\s*:\s*$`, lines[j])
	k := _parent(lines, j)
	regex.match(`^management\s*:\s*$`, lines[k])
}

_yaml_value_sensitive(_, _, v) if {
	v != ""
	regex.match(_sensitive, v)
}

# block list:  include:\n  - health\n  - heapdump
_yaml_value_sensitive(lines, i, "") if {
	ii := _indent(lines[i])
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
	_in_list(lines, i, k, ii)
	m := regex.find_all_string_submatch_n(`^\s*-\s*(.*)$`, lines[k], 1)
	count(m) > 0
	regex.match(_sensitive, trim_space(m[0][1]))
}

_in_list(lines, i, k, ii) if {
	not _list_ended(lines, i, k, ii)
}

_list_ended(lines, i, k, ii) if {
	some m in numbers.range(i + 1, k)
	trim_space(lines[m]) != ""
	not regex.match(`^\s*-`, lines[m])
	_indent(lines[m]) <= ii
}

# The nearest non-blank line above i with a smaller indent.
_parent(lines, i) := j if {
	ii := _indent(lines[i])
	cands := [k |
		some k in numbers.range(max([0, i - 12]), i - 1)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
		_indent(lines[k]) < ii
	]
	count(cands) > 0
	j := cands[count(cands) - 1]
}

# The full dotted key of an include line, read from its YAML ancestors (each
# non-blank line above with a smaller indent than every line between it and
# the include), must be management.endpoints.web.exposure.include: an include
# under jmx, or under an unrelated mapping, exposes nothing over HTTP.
_under_web_exposure(lines, i, own) if {
	ii := _indent(lines[i])
	anc := [k |
		some k in numbers.range(max([0, i - 40]), i - 1)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
		_indent(lines[k]) < ii
		not _closed(lines, k, i)
	]
	count(anc) > 0
	_indent(lines[anc[0]]) == 0
	keys := [key | some k in anc; key := trim_space(split(lines[k], ":")[0])]
	concat(".", array.concat(keys, [own])) == "management.endpoints.web.exposure.include"
}

# A line between k and i at or left of k's indent closes k's block.
_closed(lines, k, i) if {
	k + 1 < i
	some m in numbers.range(k + 1, i - 1)
	trim_space(lines[m]) != ""
	not helpers.is_comment_line(lines[m])
	_indent(lines[m]) <= _indent(lines[k])
}

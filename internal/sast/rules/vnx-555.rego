# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_555

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-555",
	"name": "J2EE Misconfiguration: Plaintext Password in Configuration File",
	"description": "A literal password is written into a Java EE / Jakarta EE deployment descriptor or application-server configuration file: web.xml, context.xml, server.xml, tomcat-users.xml, persistence.xml, ejb-jar.xml, application.xml, ra.xml, JBoss/WildFly standalone*.xml, domain.xml, host.xml and *-ds.xml, GlassFish glassfish-resources.xml/sun-resources.xml/domain.xml, WebLogic weblogic*.xml, jboss*.xml, jetty*.xml, resin.xml, ibm-*.xml and hibernate.cfg.xml. Reported: a password-like attribute with a literal value (password=, passwd=, keystorePass=, truststorePass=, keyPass=, connectionPassword=, as on a Tomcat <Resource>, <user> or <Connector>); an element whose name ends in password/passwd with a literal body (<password>, <xa-datasource-property name=...>); a <property name=\"...password\" value=\"...\"> (JPA and Hibernate) and a Tomcat <Environment>/<Parameter> whose name ends in password with a literal value= (attributes in any order); and a web.xml <param-value> or <env-entry-value> whose preceding <param-name>/<env-entry-name> ends in password/passwd/pwd. Not reported: empty values, references and placeholders (${...}, #{...}, @token@, %name%), encoded values ({aes}, {xor}, ENC(...)), mask and placeholder words (****, changeme, your-password), names that only contain the word (passwordEncoder, password.encoder), XML comments including multi-line blocks, other XML files, config templates (.example, .sample, .template, .dist) and test resources. VNX-260 reports passwords in configuration files generally and leaves the lines this rule reports in these files to it; password=\"...\" attributes are also reported by VNX-SEC-014.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-555/",
	"languages": ["java", "xml"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [555],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["j2ee-credentials", "plaintext-password", "cwe-555"],
}

_j2ee_re := `^(web|context|server|tomcat-users|persistence|ejb-jar|application|ra|domain|host|glassfish-resources|sun-resources|glassfish-web|sun-web|resin|hibernate\.cfg)\.xml$|^(standalone|weblogic|jboss|jetty|ibm-)[\w.-]*\.xml$|-ds\.xml$`

_j2ee_file(path) if {
	base := lower(regex.replace(path, `^.*/`, ""))
	regex.match(_j2ee_re, base)
	not helpers.is_test_path(path)
	not regex.match(`(?i)\.(example|sample|template|dist|tmpl)(\.|$)`, path)
}

_name := `(?i:password|passwd|pwd)`

_attr_re := `(?i)\b(?:password|passwd|keystorePass|truststorePass|keyPass|connectionPassword|keystorePassword|truststorePassword|clear-text)\s*=\s*(?:"([^"]*)"|'([^']*)')`

_elem_re := `<([\w.:-]*(?i:password|passwd))>\s*([^<]*?)\s*</`

_prop_re := `(?i)<property\s+name\s*=\s*["'][^"']*(?:password|passwd|pwd)["']\s+value\s*=\s*(?:"([^"]*)"|'([^']*)')`

# Hibernate <property name="...password">value</property> and Jetty
# <Set name="password">value</Set> / <Put name="password">value</Put>.
_named_body_re := `(?i)<(?:property|set|put)\s+name\s*=\s*["'][^"']*(?:password|passwd|pwd)["']\s*>\s*([^<]*?)\s*</`

# Tomcat <Environment>/<Parameter> (and <property>) with name="...password"
# and a value= attribute, in either order and with other attributes between.
_named_attr_res := [
	`(?i)<(?:Environment|Parameter|property)\b[^>]*?\bname\s*=\s*["'][^"']*(?:password|passwd|pwd)["'][^>]*?\svalue\s*=\s*(?:"([^"]*)"|'([^']*)')`,
	`(?i)<(?:Environment|Parameter|property)\b[^>]*?\svalue\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*?\bname\s*=\s*["'][^"']*(?:password|passwd|pwd)["']`,
]

_value_elem_re :=`<(?:param-value|env-entry-value)>\s*([^<]*?)\s*</`

_placeholder := `(?i)^(?:|\$\{.*|#\{.*|@[\w.-]+@|%[\w.-]+%|\$\(.*|\{[a-z0-9_-]+\}.*|ENC\(.*|\*+|x{3,}|\.\.\.|<.*>|changeme|change[_-]?me|placeholder|your[_-]?password|todo|tbd|none|null)$`

_literal(v) if {
	v != ""
	not regex.match(_placeholder, v)
}

_values(line) := vs if {
	attr := [v |
		some m in regex.find_all_string_submatch_n(_attr_re, line, -1)
		v := concat("", [m[1], m[2]])
	]
	elem := [m[2] | some m in regex.find_all_string_submatch_n(_elem_re, line, -1)]
	prop := [v |
		some m in regex.find_all_string_submatch_n(_prop_re, line, -1)
		v := concat("", [m[1], m[2]])
	]
	body := [m[1] | some m in regex.find_all_string_submatch_n(_named_body_re, line, -1)]
	named := [v |
		some re in _named_attr_res
		some m in regex.find_all_string_submatch_n(re, line, -1)
		v := concat("", [m[1], m[2]])
	]
	vs := array.concat(array.concat(array.concat(array.concat(attr, elem), prop), body), named)
}

# A <param-value>/<env-entry-value> whose name (within the three lines above)
# is a password.
_param_value(lines, i, line) := v if {
	m := regex.find_all_string_submatch_n(_value_elem_re, line, 1)
	count(m) > 0
	v := m[0][1]
	some k in numbers.range(max([0, i - 3]), i - 1)
	regex.match(concat("", [`<(?:param-name|env-entry-name)>[^<]*`, _name, `\s*</`]), lines[k])
}

_in_comment(lines, i, _) if {
	before := concat("\n", array.slice(lines, 0, i))
	count(indexof_n(before, "<!--")) > count(indexof_n(before, "-->"))
}

_in_comment(_, _, line) if {
	k := indexof(line, "<!--")
	k >= 0
	trim_space(substring(line, 0, k)) == ""
}

_hit(lines, i, line) if {
	some v in _values(line)
	_literal(v)
}

_hit(lines, i, line) if {
	v := _param_value(lines, i, line)
	_literal(v)
}

findings contains finding if {
	some path, content in input.file_contents
	_j2ee_file(path)
	regex.match(`(?i)pass|pwd`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pass|pwd|<param-value>|<env-entry-value>`, line)
	_hit(lines, i, line)
	not _in_comment(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Plaintext password in a J2EE configuration file; reference it from the server's credential store, an environment variable or an encrypted vault instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

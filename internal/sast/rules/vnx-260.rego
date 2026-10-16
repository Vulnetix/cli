# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_260

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-260",
	"name": "Password in Configuration File",
	"description": "A literal password is written into a configuration file in one of the shapes the generic hard-coded password rule (VNX-SEC-014, which covers YAML, .properties, .ini, .conf, .env, JSON keys and password=\"...\" attributes) does not read. Reported: an XML element whose name ends in password/passwd (<password>, <smtpPassword>, <jdbc.password>) with a literal body (Maven settings.xml, Hibernate, Tomcat and Spring XML); an XML <property>, <prop>, <entry>, <param>, <parameter>, <add>, <setting> or <context-param> whose name or key ends in password/passwd/pwd and whose value attribute or body is a literal (Spring beans, .NET Web.config/App.config appSettings, Java properties-in-XML); an XML attribute named for the password (Tomcat <Resource password=...>, tomcat-users and Spring Security <user password=...> including {noop} values, ASP.NET forms <user password=...>, a Connector keystorePass/truststorePass/keyPass); the Password=/Pwd= key of a connectionString attribute (Web.config, App.config); PHP define('..._PASSWORD'|'..._PASS'|'..._PWD', '...') anywhere, and $config[...]['..password'] = '...' array entries in PHP files whose path names a config, settings, database or local file (config.inc.php, wp-config.php, LocalSettings.php); credential dotfiles: .netrc/_netrc password entries, .pgpass lines, .pypirc password = ..., and .npmrc _password=/_auth=. Not reported: placeholders and references (${...}, #{...}, {{...}}, %(name)s, @token@, $(...), <...>, ****), encrypted values (Maven {...}, Jasypt ENC(...), Spring {cipher}), empty values, labels (values with spaces, the word Password itself), names that only contain the word (passwordEncoder, password_hint, PASSWORD_MIN_LENGTH, password-parameter, android:inputType=\"textPassword\"), boolean attribute values (android:password=\"true\"), connection strings with no Password key (Integrated Security), XML comments, config templates (.example, .sample, .template, .dist) and test resources. A password in a Java EE deployment descriptor or application-server file (server.xml, context.xml, tomcat-users.xml, web.xml, persistence.xml, hibernate.cfg.xml, standalone*.xml, *-ds.xml and the rest of VNX-555's list) that VNX-555 reads is reported by VNX-555, not here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-260/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [260],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["password-in-config", "cwe-260"],
}

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(^|/)src/test/`, path)

_skip(path) if regex.match(`(?i)\.(example|sample|template|tmpl|dist|md|rst|txt)$`, path)

_skip(path) if regex.match(`(?i)(^|/)[^/]*\.(example|sample|template|dist)\.[^/]+$`, path)

_kind(path) := "xml" if regex.match(`(?i)\.(xml|config|xsd-config|jelly|properties\.xml)$`, path)

_kind(path) := "php" if endswith(path, ".php")

_kind(path) := "netrc" if regex.match(`(^|/)[._]netrc$`, path)

_kind(path) := "pgpass" if regex.match(`(^|/)\.pgpass$`, path)

_kind(path) := "pypirc" if regex.match(`(^|/)\.pypirc$`, path)

_kind(path) := "npmrc" if regex.match(`(^|/)\.npmrc$`, path)

_gate("xml") := `(?i)pass|pwd`

_gate("php") := `(?i)pass|pwd`

_gate("netrc") := `password`

_gate("pgpass") := `:`

_gate("pypirc") := `password`

_gate("npmrc") := `_password|_auth\s*=`

_pw_word := `(?:[Pp]assword|PASSWORD|[Pp]asswd|PASSWD|[Pp]wd|PWD)`

_patterns("xml") := [
	concat("", [`<[\w.:\-]*`, _pw_word, `>\s*([^<]*?)\s*</[\w.:\-]*`, _pw_word, `>`]),
	concat("", [`<(?:property|prop|entry|param|parameter|Parameter|setting|add|context-param)\b[^>]*\b(?:name|key)\s*=\s*["'][\w.\-:]*`, _pw_word, `["'][^>]*\bvalue\s*=\s*["']([^"']*)["']`]),
	concat("", [`<(?:property|prop|entry|param|parameter|Parameter|setting)\b[^>]*\b(?:name|key)\s*=\s*["'][\w.\-:]*`, _pw_word, `["'][^>/]*>\s*([^<]*?)\s*<`]),
	# An attribute named for the password: Tomcat <Resource password=...>,
	# tomcat-users <user password=...>, Spring Security <user password=...>,
	# a Connector keystorePass=...
	concat("", [`(?:^|\s)[\w.:\-]*(?:`, _pw_word, `|[Kk]ey[Ss]tore[Pp]ass|[Tt]rust[Ss]tore[Pp]ass|[Kk]ey[Pp]ass)\s*=\s*["']([^"']*)["']`]),
	# The Password=/Pwd= key of an ADO.NET connection string attribute.
	`(?i)\bconnectionString\s*=\s*["'][^"']*?(?:^|[;"'\s])(?:password|pwd)\s*=\s*([^;"']*)`,
]

_patterns("php") := [concat("", [`\bdefine\s*\(\s*['"]\w*(?:PASSWORD|PASSWD|PASS|PWD)['"]\s*,\s*['"]([^'"]*)['"]\s*\)`])]

_patterns("netrc") := [`(?:^|\s)password\s+(\S+)`]

_patterns("pgpass") := [`^[^:#\s]+:[^:\s]+:[^:\s]+:[^:\s]+:(\S+)\s*$`]

_patterns("pypirc") := [`^\s*password\s*[:=]\s*(\S+)\s*$`]

_patterns("npmrc") := [`(?:^|:)_(?:password|auth)\s*=\s*(\S+)\s*$`]

# PHP array entries count only in a configuration file.
_php_config(path) if regex.match(`(?i)(^|/)(?:[^/]*(?:conf|config|settings|setup|database|db|local|env)[^/]*\.php|config/[^/]+\.php)$`, path)

_php_array := concat("", [`^\s*\$\w+(?:\s*\[\s*(?:['"][^'"]*['"]|\$\w+)\s*\])*\s*\[\s*['"]\w*(?i:password|passwd|pass|pwd)['"]\s*\]\s*=\s*['"]([^'"]*)['"]\s*;`])

_extra(path, line) := v if {
	_php_config(path)
	m := regex.find_all_string_submatch_n(_php_array, line, 1)
	count(m) > 0
	v := m[0][1]
}

_placeholder(v) if trim_space(v) == ""

_placeholder(v) if regex.match(`\s`, trim_space(v))

_placeholder(v) if regex.match(`\$\{|#\{|\{\{|%\(|\$\(|^\$\w|^@[\w.\-]+@$|^<.*>$|^\*+$|^ENC\(|^\{[A-Za-z0-9+/=]+\}$|^\{(?:cipher|bcrypt|sha|ssha|pbkdf2|scrypt|argon2)\}`, v)

_placeholder(v) if regex.match(`(?i)^(?:changeme|change_me|your[-_].*|x{3,}|placeholder|redacted|secret|password|passwd|none|null|nil|true|false|required|\*)$`, v)

# A label: letters and separators containing the word.
_placeholder(v) if regex.match(`(?i)^[a-z_.\-]*pass(?:word|wd)?[a-z_.\-]*$`, v)

# Inside a multi-line XML comment opened above and not yet closed.
_in_xml_comment(lines, i) if contains(lines[i], "<!--")

_in_xml_comment(lines, i) if {
	i > 0
	some k in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[k], "<!--")
	not contains(substring(lines[k], indexof(lines[k], "<!--"), -1), "-->")
	not _closed_between(lines, k, i)
}

_closed_between(lines, k, i) if {
	k + 1 <= i - 1
	some m in numbers.range(k + 1, i - 1)
	contains(lines[m], "-->")
}

_values(kind, path, line) := {v |
	some pat in _patterns(kind)
	some m in regex.find_all_string_submatch_n(pat, line, -1)
	v := m[1]
} | {v | kind == "php"; v := _extra(path, line)}

findings contains finding if {
	some path, content in input.file_contents
	kind := _kind(path)
	not _skip(path)
	regex.match(_gate(kind), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate(kind), line)
	not _comment(kind, lines, i)
	some v in _values(kind, path, line)
	not _placeholder(v)
	not _owned_by_vnx555(path, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Literal password in a configuration file; reference a secret store or an environment variable instead, and rotate this password",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_comment("xml", lines, i) if _in_xml_comment(lines, i)

_comment(kind, lines, i) if {
	not kind in {"xml", "npmrc"}
	helpers.is_comment_line(lines[i])
}

# ── J2EE descriptors reported by VNX-555 ────────────────────────────────
# VNX-555 is the Java EE form of this weakness and owns a password in a
# deployment descriptor or application-server file (server.xml, context.xml,
# tomcat-users.xml, web.xml, persistence.xml, standalone*.xml, *-ds.xml...).
# These predicates are VNX-555's own, so every line handed over here is
# reported there.

_v555_j2ee_re := `^(web|context|server|tomcat-users|persistence|ejb-jar|application|ra|domain|host|glassfish-resources|sun-resources|glassfish-web|sun-web|resin|hibernate\.cfg)\.xml$|^(standalone|weblogic|jboss|jetty|ibm-)[\w.-]*\.xml$|-ds\.xml$`

_owned_by_vnx555(path, lines, i, line) if {
	endswith(lower(path), ".xml")
	regex.match(_v555_j2ee_re, lower(regex.replace(path, `^.*/`, "")))
	not helpers.is_test_path(path)
	not regex.match(`(?i)\.(example|sample|template|dist|tmpl)(\.|$)`, path)
	_v555_hit(lines, i, line)
	not _v555_in_comment(lines, i, line)
}

_v555_placeholder := `(?i)^(?:|\$\{.*|#\{.*|@[\w.-]+@|%[\w.-]+%|\$\(.*|\{[a-z0-9_-]+\}.*|ENC\(.*|\*+|x{3,}|\.\.\.|<.*>|changeme|change[_-]?me|placeholder|your[_-]?password|todo|tbd|none|null)$`

_v555_res := [
	`(?i)\b(?:password|passwd|keystorePass|truststorePass|keyPass|connectionPassword|keystorePassword|truststorePassword|clear-text)\s*=\s*(?:"([^"]*)"|'([^']*)')`,
	`(?i)<property\s+name\s*=\s*["'][^"']*(?:password|passwd|pwd)["']\s+value\s*=\s*(?:"([^"]*)"|'([^']*)')`,
	`(?i)<(?:Environment|Parameter|property)\b[^>]*?\bname\s*=\s*["'][^"']*(?:password|passwd|pwd)["'][^>]*?\svalue\s*=\s*(?:"([^"]*)"|'([^']*)')`,
	`(?i)<(?:Environment|Parameter|property)\b[^>]*?\svalue\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*?\bname\s*=\s*["'][^"']*(?:password|passwd|pwd)["']`,
]

_v555_values(line) := (({v |
	some re in _v555_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	v := concat("", [m[1], m[2]])
} | {m[2] |
	some m in regex.find_all_string_submatch_n(`<([\w.:-]*(?i:password|passwd))>\s*([^<]*?)\s*</`, line, -1)
}) | {m[1] |
	some m in regex.find_all_string_submatch_n(`(?i)<(?:property|set|put)\s+name\s*=\s*["'][^"']*(?:password|passwd|pwd)["']\s*>\s*([^<]*?)\s*</`, line, -1)
})

_v555_hit(_, _, line) if {
	some v in _v555_values(line)
	v != ""
	not regex.match(_v555_placeholder, v)
}

_v555_hit(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`<(?:param-value|env-entry-value)>\s*([^<]*?)\s*</`, line, 1)
	count(m) > 0
	v := m[0][1]
	v != ""
	not regex.match(_v555_placeholder, v)
	some k in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`<(?:param-name|env-entry-name)>[^<]*(?i:password|passwd|pwd)\s*</`, lines[k])
}

_v555_in_comment(lines, i, _) if {
	before := concat("\n", array.slice(lines, 0, i))
	count(indexof_n(before, "<!--")) > count(indexof_n(before, "-->"))
}

_v555_in_comment(_, _, line) if {
	k := indexof(line, "<!--")
	k >= 0
	trim_space(substring(line, 0, k)) == ""
}

# .npmrc keys begin with // (a registry URL); only # starts a comment.
_comment("npmrc", lines, i) if startswith(trim_space(lines[i]), "#")

_comment(kind, lines, i) if {
	kind != "xml"
	startswith(trim_space(lines[i]), ";")
}

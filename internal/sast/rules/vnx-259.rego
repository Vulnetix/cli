# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_259

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-259",
	"name": "Hard-coded password passed to an authentication or connection API",
	"description": "A string literal is passed as the password argument of a call that authenticates or opens a connection, so the password ships in the source and cannot be rotated without a release. Positional arguments are what this rule covers; a literal assigned to a password-named variable, key, keyword argument or configuration entry is reported by VNX-SEC-014 (and in Java by VNX-JAVA-025). Reported: Python .login(user, \"pw\") (smtplib, ftplib, imaplib; the user may be a literal or a variable), HTTPBasicAuth/HTTPDigestAuth(user, \"pw\"), requests auth=(\"u\", \"pw\"), pymysql/MySQLdb.connect(host, user, \"pw\"), LDAP simple_bind(_s)(dn, \"pw\"); Java env.put(Context.SECURITY_CREDENTIALS, \"pw\"), Transport.send(msg, user, \"pw\"), transport.connect(host, user, \"pw\"), new UsernamePasswordAuthenticationToken(\"u\", \"pw\"), DriverManager.getConnection(url, user, \"pw\"), new PasswordAuthentication(user, \"pw\".toCharArray()); JavaScript new Sequelize(db, user, \"pw\"), a pass: \"pw\" member inside an auth: { } object (nodemailer), express-basic-auth users: { name: \"pw\" }, .auth(\"u\", \"pw\"), ldapjs client.bind(\"cn=...\", \"pw\") (the first literal must look like a DN or UPN, so Function.prototype.bind and jQuery bind are not matched); PHP mysqli_connect/new mysqli/mysql_connect(host, user, \"pw\"), new PDO(dsn, user, \"pw\"), ldap_bind(conn, dn, \"pw\"), ftp_login(conn, user, \"pw\"); Ruby ftp.login(user, \"pw\"), .basic_auth(user, \"pw\"), Net::SMTP.start(host, port, helo, user, \"pw\", ...); Go smtp.PlainAuth(identity, user, \"pw\", host), SetBasicAuth(user, \"pw\"), url.UserPassword(user, \"pw\"), ssh.Password(\"pw\"), go-ldap conn.Bind(\"cn=...\", \"pw\"); C# new NetworkCredential(user, \"pw\"). Not reported: values from the environment, configuration or a variable, empty strings, interpolated or templated values (${...}, {{...}}, %s, $var), placeholders (xxx, ***, <password>, your-password, or the bare words password, pass, secret, user), comments, strings that only mention the call, and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-259/",
	"languages": ["csharp", "go", "java", "node", "php", "python", "ruby"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [259],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["hardcoded-credentials", "cwe-259"],
}

_skip(path) if helpers.is_test_path(path)

_skip(path) if regex.match(`(^|/)(Tests?|Specs?|[A-Za-z]+Tests|[A-Za-z.]+\.Tests?)/`, path)

_skip(path) if regex.match(`(?i)\.(example|sample|template|dist)$`, path)

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if regex.match(`\.(js|jsx|ts|tsx|mjs|cjs)$`, path)

_lang(path) := "java" if regex.match(`\.(java|kt)$`, path)

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "ruby" if endswith(path, ".rb")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "csharp" if endswith(path, ".cs")

# A quoted literal; group 1 is its text.
_lit := `["']([^"'\\\n]*)["']`

# An argument that is not the password (anything without a top-level comma).
_any := `(?:"[^"\n]*"|'[^'\n]*'|[^,()]+(?:\([^()]*\)[^,()]*)?)`

_patterns("python") := [
	concat("", [`\.login\(\s*`, _any, `,\s*`, _lit, `\s*\)`]),
	concat("", [`\bHTTP(?:Basic|Digest|Proxy)Auth\(\s*`, _any, `,\s*`, _lit]),
	concat("", [`\bauth\s*=\s*\(\s*`, _lit, `\s*,\s*`, _lit, `\s*\)`]),
	concat("", [`\b(?:pymysql|MySQLdb|mysql\.connector)\.connect\(\s*`, _any, `,\s*`, _any, `,\s*`, _lit]),
	concat("", [`\.simple_bind(?:_s)?\(\s*`, _any, `,\s*`, _lit]),
]

_patterns("java") := [
	concat("", [`Context\.SECURITY_CREDENTIALS\s*,\s*`, _lit]),
	concat("", [`\bTransport\.send\(\s*`, _any, `,\s*`, _any, `,\s*`, _lit, `\s*\)`]),
	concat("", [`\b\w*[tT]ransport\.connect\(\s*`, _any, `,\s*`, _any, `,\s*`, _lit, `\s*\)`]),
	concat("", [`\bnew\s+UsernamePasswordAuthenticationToken\(\s*`, _lit, `\s*,\s*`, _lit]),
	concat("", [`\bDriverManager\.getConnection\(\s*`, _any, `,\s*`, _any, `,\s*`, _lit, `\s*\)`]),
	concat("", [`\b(?:new\s+)?PasswordAuthentication\(\s*`, _any, `,\s*`, _lit, `\s*\.toCharArray\(\)`]),
]

_patterns("node") := [
	concat("", [`\bnew\s+Sequelize\(\s*`, _any, `,\s*`, _any, `,\s*`, _lit]),
	concat("", [`\busers\s*:\s*\{\s*["']?\w+["']?\s*:\s*`, _lit]),
	concat("", [`\.auth\(\s*`, _lit, `\s*,\s*`, _lit, `\s*[,)]`]),
	# ldapjs client.bind(dn, password, cb): the DN names an entry (cn=, uid=) or a UPN.
	concat("", [`\.bind\(\s*["'][^"'\n]*[=@][^"'\n]*["']\s*,\s*`, _lit, `\s*[,)]`]),
]

_patterns("php") := [
	concat("", [`\b(?:mysqli_connect|mysql_connect|mysql_pconnect|new\s+mysqli)\s*\(\s*`, _any, `,\s*`, _any, `,\s*`, _lit]),
	concat("", [`\bnew\s+PDO\s*\(\s*`, _any, `,\s*`, _any, `,\s*`, _lit]),
	concat("", [`\b(?:ldap_bind|ftp_login|ssh2_auth_password)\s*\(\s*`, _any, `,\s*`, _any, `,\s*`, _lit]),
]

_patterns("ruby") := [
	concat("", [`\.login\(\s*`, _any, `,\s*`, _lit, `\s*\)`]),
	concat("", [`\.basic_auth\(\s*`, _any, `,\s*`, _lit, `\s*\)`]),
	# Net::SMTP.start(address, port, helo, user, secret, authtype)
	concat("", [`\bNet::SMTP\.start\(\s*`, _any, `,\s*`, _any, `,\s*`, _any, `,\s*`, _any, `,\s*`, _lit]),
]

_patterns("go") := [
	concat("", [`\bsmtp\.PlainAuth\(\s*`, _any, `,\s*`, _any, `,\s*"([^"\\\n]*)"`]),
	concat("", [`\.SetBasicAuth\(\s*`, _any, `,\s*"([^"\\\n]*)"\s*\)`]),
	concat("", [`\burl\.UserPassword\(\s*`, _any, `,\s*"([^"\\\n]*)"\s*\)`]),
	`\bssh\.Password\(\s*"([^"\\\n]*)"\s*\)`,
	# go-ldap conn.Bind(dn, password): the DN literal names an entry or a UPN.
	`\.Bind\(\s*"[^"\n]*[=@][^"\n]*"\s*,\s*"([^"\\\n]*)"\s*\)`,
]

_patterns("csharp") := [concat("", [`\bnew\s+NetworkCredential\s*\(\s*`, _any, `,\s*@?"([^"\\\n]*)"`])]

_gate("python") := `login\(|Auth\(|auth\s*=|connect\(|simple_bind`

_gate("java") := `SECURITY_CREDENTIALS|Transport|UsernamePasswordAuthenticationToken|ransport\.connect|getConnection|PasswordAuthentication`

_gate("node") := `Sequelize|users\s*:|\.auth\(|pass\s*:|\.bind\(`

_gate("php") := `connect|mysqli|PDO|ldap_bind|ftp_login|ssh2_auth_password`

_gate("ruby") := `\.login\(|basic_auth|SMTP\.start`

_gate("go") := `PlainAuth|SetBasicAuth|UserPassword|ssh\.Password|\.Bind\(`

_gate("csharp") := `NetworkCredential`

# The password is the last captured literal of the match.
_password(m) := m[count(m) - 1]

_placeholder(v) if trim_space(v) == ""

_placeholder(v) if regex.match(`\$\{|\{\{|%[sdv(]|^\$\w|^\{\w*\}$|^<.*>$|^\*{3,}$|^(?i:x{3,}|\.\.\.|placeholder|redacted|changeme|password|passwd|pass|username|user|secret|your[-_ ].*|enter[-_ ].*)$`, v)

# Line starts inside a string literal (odd number of quotes before the match).
_in_string(line, idx) if {
	before := substring(line, 0, idx)
	q := count(regex.find_all_string_submatch_n(`["'\x60]`, before, -1))
	q % 2 == 1
}

_message := "Hard-coded password passed to an authentication/connection call; read it from a secret store or the environment at runtime"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not _skip(path)
	regex.match(_gate(lang), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	not helpers.is_comment_line(line)
	some pat in _patterns(lang)
	some m in regex.find_all_string_submatch_n(pat, line, -1)
	not _placeholder(_password(m))
	not _in_string(line, indexof(line, m[0]))
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# nodemailer and similar: `pass: "..."` inside an `auth: {` object.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "node"
	not _skip(path)
	regex.match(`auth\s*:\s*\{`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "pass")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[\s{,])pass\s*:\s*`, _lit]), line, 1)
	count(m) > 0
	not _placeholder(m[0][1])
	_in_auth_object(lines, i)
	not _in_string(line, indexof(line, m[0][0]))
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_in_auth_object(lines, i) if regex.match(`auth\s*:\s*\{`, lines[i])

_in_auth_object(lines, i) if {
	some k in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`auth\s*:\s*\{\s*$`, lines[k])
}

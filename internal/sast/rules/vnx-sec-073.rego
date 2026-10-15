package vulnetix.rules.vnx_sec_073

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-073",
	"name": "URL with embedded credentials",
	"description": "Reports a web or file-transfer URL that embeds a literal password: http://, https://, ws://, wss://, ftp://, ftps:// or sftp://user:password@host (also git+https:// and an empty user, https://:token@host), in code, config (pip.conf, .npmrc, YAML, .env) and scripts. Credentials in a URL end up in proxy, server and CDN logs, shell history and process listings. The password is masked in the snippet. Not reported: a password that is interpolated or templated (${VAR}, $VAR, %VAR%, {{ }}, %s, <password>, f-string or template-literal fields, string concatenation), a default or placeholder word (password, changeme, admin, the user name itself, an upper-case name such as API_KEY...), *** masks, a host on localhost/127.0.0.1/::1 or a placeholder host (example.com, host, hostname), URLs with no password, database and message-broker schemes (postgres://, mysql://, mongodb://, redis://, amqp://), which VNX-SEC-008, VNX-SEC-061 to VNX-SEC-064 and VNX-SEC-578 report, Markdown/reStructuredText/AsciiDoc and *.example/*.sample/*.template files, and test, fixture, vendored and generated files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-073/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "url", "credentials"],
}

# scheme://user:password@host  (groups: user, password, host)
_url := "(?i)(?:^|[^a-z0-9.+-])(?:git\\+|svn\\+)?(?:https?|wss?|ftps?|sftp)://([^\\s:@/'\"`<>]*):([^\\s@/'\"`<>]+)@(\\[[0-9a-f:]+\\]|[a-z0-9_.-]+)"

_doc_suffix := [".md", ".markdown", ".rst", ".adoc", ".example", ".sample", ".template", ".dist", ".tmpl"]

_skip(path) if {
	low := lower(path)
	some s in _doc_suffix
	endswith(low, s)
}

_skip(path) if regex.match(`(?i)\.(example|sample|template)\.[a-z0-9]+$`, path)

# Kotlin multiplatform and Gradle test source sets (src/jvmTest/,
# src/androidTest/, src/integrationTest/) that is_test_path does not name.
_skip(path) if regex.match(`(?:^|/)src/[A-Za-z]*Test/`, path)

_defaults := {
	"password", "passwd", "pass", "pwd", "pw", "secret", "changeme", "change_me",
	"root", "admin", "administrator", "test", "testing", "example", "user",
	"username", "guest", "default", "token", "apikey", "api_key", "key",
	"mypassword", "pass123", "password123", "123456", "secretpassword",
	"mysecretpassword", "foo", "bar", "baz", "anonymous", "demo",
}

_weak_password(user, pw) if lower(pw) == lower(user)

_weak_password(_, pw) if _defaults[lower(pw)]

# Interpolation and templating: ${X}, $X, {{ x }}, {x}, <password>, %s,
# %(x)s, *** and ... masks.
_weak_password(_, pw) if regex.match(`[$\{\}<>*]|%[sdvq(]|\.\.\.|^:`, pw)

_weak_password(_, pw) if secrets.is_placeholder(pw)

# Windows batch variables (%GIT_TOKEN%) are expanded at run time.
_weak_password(_, pw) if regex.match(`%[A-Za-z_][A-Za-z0-9_]*%`, pw)

# An upper-case identifier such as API_KEY or ACCESS_TOKEN names the value a
# reader is to substitute; it is not the value.
_weak_password(_, pw) if regex.match(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`, pw)

_weak_password(_, pw) if regex.match(`(?i)your|placeholder|redacted|changeme|^x+$`, pw)

# A port written after a bare host ("https://cdn.acme.io:8443/x@2x.png")
# never reaches the "@": the password class excludes "/".  A purely numeric
# "password" is a host:port pair in front of a path-less "@" and is no
# credential.
_weak_password(_, pw) if regex.match(`^[0-9]{1,5}$`, pw)

# One to three characters ("http://a:b@c/") is a URL-parser example, not a
# credential anyone issues.
_weak_password(_, pw) if count(pw) < 4

_loopback(host) if regex.match(`(?i)^(localhost|127\.[0-9.]+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)$`, host)

_loopback(host) if regex.match(`(?i)^(host|hostname|server|domain|example\.(com|org|net)|[a-z0-9.-]*\.example(\.com)?)$`, host)

_url_creds(line) := {[m[2], m[3]] |
	some m in regex.find_all_string_submatch_n(_url, line, -1)
	not _weak_password(m[1], m[2])
	not _loopback(m[3])
}

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "://")
	contains(content, "@")
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not _skip(path)
	regex.match(`://[^\s:@/'"<>]*:[^\s@/'"<>]+@`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "@")
	some cred in _url_creds(line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("URL for %s embeds a password; rotate the credential and pass it through a credential helper, netrc or a secrets manager instead of the URL", [cred[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, cred[0], "***"),
	}
}

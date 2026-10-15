package vulnetix.rules.vnx_sec_067

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-067",
	"name": "Curl command with embedded credentials",
	"description": "Reports a curl invocation that passes a literal credential with -u/--user: -u user:password, -uuser:password, --user user:password and --user=user:password (quoted or bare), on the curl line itself, on a backslash-continued line of the same curl command, or as the argument after \"-u\" in an argv list (subprocess.run([\"curl\", \"-u\", \"user:pw\", ...]), exec.Command(\"curl\", \"-u\", ...), including a list split over lines up to 6 lines below its \"curl\" element); also an API key passed as the user with an empty password (-u sk_xxx:) when the key is long and high-entropy. Scripts, Dockerfiles, CI workflows, Makefiles and code strings are covered. The password is masked in the snippet. Not reported: credentials that reference a variable or command ($VAR, ${VAR}, $(...), {{ }}, %s, <password>), a user with no password (curl prompts for it) and --negotiate -u :, default or placeholder pairs (user:password, admin:admin, changeme, a password equal to the user), -u of another command (sudo -u, docker run -u, a command after a pipe or &&), comment lines, Markdown/reStructuredText/AsciiDoc and *.example/*.sample files, and test, fixture, vendored and generated files. VNX-BASH-005 also reports curl -u user:VALUE in shell scripts.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-067/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "curl", "credentials"],
}

_doc_suffix := [".md", ".markdown", ".rst", ".adoc", ".example", ".sample", ".template", ".dist", ".tmpl"]

_skip(path) if {
	low := lower(path)
	some s in _doc_suffix
	endswith(low, s)
}

# -u / --user flag followed by user:password (groups: user, password).
_flag := `(?:^|[\s'"])(?:-u\s*|--user(?:\s+|=))['"]?([^\s'":|;&]*):([^\s'"|;&]*)`

# argv list form: "-u", "user:password"
_argv := `['"](?:-u|--user)['"]\s*,\s*['"]([^\s'":]*):([^\s'"]*)['"]`

# The part of a line from a curl command word to the next command separator.
_curl_segment := `(?:^|[\s'"(\x60])curl(?:\.exe)?\b[^|;&\n]*`

_defaults := {
	"password", "passwd", "pass", "pwd", "secret", "changeme", "change_me", "test",
	"testing", "example", "admin", "root", "guest", "default", "123456", "1234",
	"12345678", "password123", "pass123", "mypassword", "foo", "bar", "token",
	"apikey", "api_key", "key",
}

_weak(user, pw) if lower(user) == lower(pw)

_weak(_, pw) if _defaults[lower(pw)]

_weak(_, pw) if regex.match(`(?i)your|placeholder|redacted|changeme|example|[$<>{}%*]|\.\.\.`, pw)

_weak(_, pw) if secrets.is_placeholder(pw)

_weak(user, _) if regex.match(`[$<>{}%]`, user)

_weak(user, pw) if {
	pw == ""
	not _api_key_user(user)
}

_api_key_user(user) if {
	count(user) >= 20
	regex.match(`^[A-Za-z0-9_-]+$`, user)
	regex.match(`[0-9]`, user)
	not secrets.is_placeholder(user)
	secrets.high_entropy(user, 3.5)
}

_secret_part(user, pw) := pw if pw != ""

_secret_part(user, "") := user

# Credentials passed by a curl command written on this line.
_creds(line) := _creds_flag(line) | _creds_argv(line)

_creds_flag(line) := {[user, pw] |
	some seg in regex.find_all_string_submatch_n(_curl_segment, line, -1)
	some m in regex.find_all_string_submatch_n(_flag, seg[0], -1)
	user := m[1]
	pw := m[2]
	not _weak(user, pw)
}

_creds_argv(line) := {[user, pw] |
	contains(line, "curl")
	some m in regex.find_all_string_submatch_n(_argv, line, -1)
	user := m[1]
	pw := m[2]
	not _weak(user, pw)
}

_continues(line) if endswith(trim_right(line, " \t\r"), "\\")

# A flag line that continues a curl command started on an earlier line.
_continued_creds(lines, i) := {[user, pw] |
	some j in numbers.range(max([0, i - 8]), i - 1)
	regex.match(_curl_segment, lines[j])
	every k in numbers.range(j, i - 1) {
		_continues(lines[k])
	}
	not regex.match(`^\s*[|;&]`, lines[i])
	some m in regex.find_all_string_submatch_n(_flag, lines[i], -1)
	user := m[1]
	pw := m[2]
	not _weak(user, pw)
}

_cred_at(lines, i) := c if {
	c := _creds(lines[i])
	count(c) > 0
}

_cred_at(lines, i) := c if {
	count(_creds(lines[i])) == 0
	i > 0
	c := _continued_creds(lines, i) | _argv_list_creds(lines, i)
}

# An argv list split over lines: "curl" is an element a few lines above and
# the list has not closed in between.
_argv_list_creds(lines, i) := {[user, pw] |
	not contains(lines[i], "curl")
	some m in regex.find_all_string_submatch_n(_argv, lines[i], -1)
	some j in numbers.range(max([0, i - 6]), i - 1)
	regex.match(`['"]curl(?:\.exe)?['"]\s*,`, lines[j])
	every k in numbers.range(j, i - 1) {
		not regex.match(`[\])]\s*[),;]?\s*$`, lines[k])
	}
	user := m[1]
	pw := m[2]
	not _weak(user, pw)
}

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "curl")
	regex.match(`(?:-u|--user)[\s='",]*['"]?[^\s'":]*:`, content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not _skip(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:-u|--user)`, line)
	not helpers.is_comment_line(line)
	some cred in _cred_at(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("curl passes a hard-coded credential for %q; rotate it and supply it from ~/.netrc, a credential helper or an environment variable", [cred[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, _secret_part(cred[0], cred[1]), "***"),
	}
}

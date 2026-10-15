# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_384

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-384",
	"name": "Session Fixation",
	"description": "A Java web application authenticates a user without issuing a new session identifier, so an attacker who planted a session id in the victim's browser before login is logged in alongside them (CWE-384). Reported: Spring Security configured to keep the pre-login session (sessionFixation().none(), sessionFixation(f -> f.none()), SessionFixationConfigurer::none, and session-fixation-protection=\"none\" in XML configuration); and a servlet or controller method that checks credentials (it mentions a password, authenticate, checkPassword, login or credentials) and then stores the authenticated identity in the existing session (setAttribute with a key such as user, userId, username, loggedIn, authenticated, principal, role or a constant naming the user or principal (SESSION_USER, LOGGED_IN; not AUTHENTICATION_CHALLENGE or USER_AGENT), on request.getSession(), getSession(true) or a session variable or parameter) without calling session.invalidate() or request.changeSessionId() earlier in that method. Not reported: migrateSession()/newSession()/changeSessionId() configuration (Spring's default protects), a method that invalidates or rotates the session before storing the user, session attributes unrelated to identity (cart, locale), updates in methods that check no credentials, methods for an already logged-in user that refresh the stored identity (named change/update/reset/set...Password, Profile or Account), comments, string literals and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-384/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [384],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["session-fixation", "cwe-384"],
}

_finding(path, i, raw, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": raw,
}

_unquote(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_none_re := `\bsessionFixation\s*\(\s*\)\s*\.\s*none\s*\(\s*\)|\bsessionFixation\s*\(\s*\w+\s*->\s*\w+\s*\.\s*none\s*\(\s*\)\s*\)|\bsessionFixation\s*\(\s*[\w.]*SessionFixationConfigurer\s*::\s*none\s*\)|^\s*\.\s*none\s*\(\s*\)`

# Spring Security Java/Kotlin-style configuration turning fixation protection off.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "sessionFixation")
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "none")
	not helpers.is_comment_line(raw)
	line := _unquote(raw)
	_none_call(lines, i, line)
	finding := _finding(path, i, raw, "Session fixation protection is disabled: the session id from before login stays valid after it. Keep Spring Security's default (changeSessionId) or use migrateSession()")
}

_none_call(_, _, line) if {
	contains(line, "sessionFixation")
	regex.match(_none_re, line)
}

# `.sessionFixation()` ending one line and `.none()` starting the next.
_none_call(lines, i, line) if {
	regex.match(`^\s*\.\s*none\s*\(\s*\)`, line)
	i > 0
	regex.match(`\bsessionFixation\s*\(\s*\)\s*$`, _unquote(lines[i - 1]))
}

_none_call(_, _, line) if regex.match(`^\s*\.\s*sessionFixation\s*\(\s*\)\s*\.\s*none\s*\(\s*\)`, line)

# XML configuration.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".xml")
	contains(content, "session-fixation-protection")
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`session-fixation-protection\s*=\s*["']none["']`, raw)
	not regex.match(`^\s*<!--`, raw)
	finding := _finding(path, i, raw, "Session fixation protection is disabled: the session id from before login stays valid after it. Use session-fixation-protection=\"changeSessionId\" or \"migrateSession\"")
}

_auth_key_re := `(?i)^(?:user|username|user_?name|user_?id|uid|current_?user|logged_?user|logged_?in|is_?logged_?in|is_?authenticated|authenticated|auth|auth_?user|principal|login|account_?id|member_?id|customer_?id|role|roles|is_?admin)$`

_auth_key(key) if {
	k := trim(key, `"`)
	regex.match(_auth_key_re, k)
}

# A constant naming the identity: SESSION_USER, Constants.AUTH_USER, LOGIN_KEY.
_auth_key(key) if {
	parts := split(key, ".")
	n := parts[count(parts) - 1]
	regex.match(`^[A-Z][A-Z0-9_]*$`, n)
	regex.match(`USER|PRINCIPAL|LOGGED|AUTHENTICATED$|^AUTH(?:_KEY)?$`, n)
	not regex.match(`CHALLENGE|NONCE|STATE|TOKEN|CSRF|REDIRECT|ERROR|ATTEMPT|AGENT|COUNT|PREF|LOCALE`, n)
}

_method_re := `^\s*(?:@\w+\s+)*(?:public|protected|private)\s+[^=;]*\w+\s*\([^;]*$`

_method_start(lines, i) := s if {
	cands := [k | some k in numbers.range(max([0, i - 60]), i); regex.match(_method_re, lines[k])]
	count(cands) > 0
	s := max(cands)
}

_window(lines, s, i) := concat("\n", [l | some k in numbers.range(s, i); l := lines[k]; not helpers.is_comment_line(l)])

_auth_signal_re := `(?i)password|passwd|authenticat|checkPassword|checkCredentials|credentials|\blogin\s*\(|\.login\s*\(|signIn|sign_in`

# The session the attribute goes into: getSession() on the line, or a variable
# assigned from getSession() or declared HttpSession in the method.
_session_receiver(_, _, _, recv) if regex.match(`getSession\s*\(`, recv)

_session_receiver(lines, s, i, recv) if {
	regex.match(`^[A-Za-z_]\w*$`, recv)
	some k in numbers.range(s, i - 1)
	regex.match(concat("", [`\b`, recv, `\s*=\s*[^;]*getSession\s*\(|\bHttpSession\s+`, recv, `\b`]), lines[k])
}

# The user was already logged in: a password change or profile update
# refreshes the identity stored in the session.
_refresh(decl) if regex.match(`(?i)\b(?:change|update|reset|set)\w*(?:password|passwd|profile|account)\w*\s*\(`, decl)


findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "setAttribute")
	contains(content, "Session")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "setAttribute")
	not helpers.is_comment_line(raw)
	m := regex.find_all_string_submatch_n(`(\b[A-Za-z_]\w*|getSession\s*\([^()]*\))\s*\.\s*setAttribute\s*\(\s*("[^"]*"|[A-Za-z_][\w.]*)\s*,`, raw, 1)
	count(m) > 0
	_auth_key(m[0][2])
	s := _method_start(lines, i)
	_session_receiver(lines, s, i, m[0][1])
	w := _window(lines, s, i)
	regex.match(_auth_signal_re, w)
	not regex.match(`\.\s*invalidate\s*\(\s*\)|changeSessionId\s*\(`, w)
	not _refresh(lines[s])
	finding := _finding(path, i, raw, "Authenticated identity is stored in the session that existed before login, so a session id fixed by an attacker stays valid: call request.changeSessionId() (or invalidate the old session and create a new one) before setting it")
}

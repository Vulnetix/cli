# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_301

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-301",
	"name": "Reflection Attack in an Authentication Protocol",
	"description": "A symmetric challenge-response protocol answers a peer's challenge with exactly the computation it expects from the peer, so an attacker can open a second session, send our own challenge back to us as theirs, and replay our answer to authenticate. Reported in Python and Java when one file both answers and verifies with the same key: an HMAC over a bare challenge or nonce variable that came from the peer (a parameter of the enclosing function, or a value read with recv/read/readFully/readLine/getParameter/request in the 10 lines above) whose result is returned, sent or written (Python hmac.new/hmac.HMAC/hmac.digest(KEY, challenge[.encode()], ...); Java mac.doFinal(challenge[.getBytes(...)]) after mac.init(new SecretKeySpec(KEY, ...)) or mac.init(keyVar)), where the same key is used for another HMAC in the file and the file compares MACs (hmac.compare_digest, MessageDigest.isEqual, Arrays.equals, or == / != on an expected/digest/mac/tag value). Test code and key derivation (a MAC returned from a derive/kdf/session_key function) are not reported. Not reported: a MAC whose input binds more than the challenge (an identity or role concatenated in Python, a mac.update() before doFinal in Java), different keys for each direction, a file that only verifies or only answers, the comparison itself, and comments. Whether a bound label actually differs between the two directions is not checked.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-301/",
	"languages": ["java", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [301],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["reflection-attack", "challenge-response", "hmac", "cwe-301"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_gate := {"py": "hmac.", "java": "doFinal"}

_compare_re := `compare_digest|MessageDigest\.isEqual|Arrays\.equals|hmac\.equal`

_challenge_name := `(?i)chal|nonce`

_recv_re := `(?i)\b(recv|recvfrom|read|readFully|readLine|readline|readNBytes|receive|getParameter|getHeader)\s*\(|\brequest\.|\.json\b|\.body\b`

_header_re := {
	"py": `^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)`,
	"java": `^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)*[\w<>\[\]]+\s+\w+\s*\(([^)]*)\)`,
}

_sink_re := `\breturn\b|\b(send|sendall|sendto|write|writeBytes|reply|respond|emit|put)\w*\s*\(`

# MAC call on line i: [key, message].
_mac("py", lines, i, line) := [m[0][2], m[0][3]] if {
	m := regex.find_all_string_submatch_n(`\bhmac\.(new|digest|HMAC)\s*\(\s*([\w.]+)\s*,\s*([A-Za-z_]\w*)(?:\.encode\([^)]*\))?\s*[,)]`, line, 1)
	count(m) > 0
}

_mac("java", lines, i, line) := [k, m[0][2]] if {
	m := regex.find_all_string_submatch_n(`\b(\w+)\.doFinal\(\s*([A-Za-z_]\w*)(?:\.getBytes\([^()]*\))?\s*\)`, line, 1)
	count(m) > 0
	not _updated(lines, i, m[0][1])
	k := _java_key(lines, i)
}

# A mac.update() before doFinal binds more than the challenge.
_updated(lines, i, recv) if {
	some j in numbers.range(max([0, i - 4]), i - 1)
	regex.match(concat("", [`\b`, recv, `\.update\(`]), lines[j])
}

_java_key(lines, i) := ks[count(ks) - 1] if {
	ks := [k |
		some j in numbers.range(max([0, i - 6]), i - 1)
		k := _java_key_on(lines[j])
	]
	count(ks) > 0
}

# The key a line binds: new SecretKeySpec(KEY, ...) or mac.init(keyVar).
_java_key_on(l) := m[0][1] if {
	contains(l, "SecretKeySpec(")
	m := regex.find_all_string_submatch_n(`SecretKeySpec\(\s*([\w.]+)`, l, 1)
	count(m) > 0
} else := m[0][1] if {
	contains(l, ".init(")
	m := regex.find_all_string_submatch_n(`\.init\(\s*(?:this\.)?(\w+)\s*\)`, l, 1)
	count(m) > 0
}

# Every key used for a MAC in the file, with the line it is used on.
_key_uses("py", lines) := [[j, m[0][1]] |
	some j, l in lines
	contains(l, "hmac.")
	m := regex.find_all_string_submatch_n(`\bhmac\.(?:new|digest|HMAC)\s*\(\s*([\w.]+)`, l, 1)
	count(m) > 0
]

_key_uses("java", lines) := [[j, k] |
	some j, l in lines
	regex.match(`SecretKeySpec\(|\.init\(`, l)
	k := _java_key_on(l)
]

# Evidence that the file also verifies a MAC it receives.
_verifies(content) if regex.match(_compare_re, content)

_verifies(content) if regex.match(`(?i)\b\w*(expected|digest|mac|tag|want|good)\w*\s*(==|!=)\s*\S|\S\s*(==|!=)\s*\w*(expected|digest|mac|tag|want|good)\w*\b`, content)

# Code that only simulates a peer, and key derivation that returns an HMAC
# of a nonce as a key rather than as an answer.
_enclosing_kdf(lang, lines, i) if {
	some j in numbers.range(max([0, i - 15]), i)
	regex.match(`(?i)^\s*(?:async\s+)?def\s+\w*(derive|kdf|session_?key|expand|key_?for)\w*\s*\(|^\s*(?:(?:public|private|protected|static|final)\s+)*[\w<>\[\]]+\s+\w*(derive|Derive|kdf|Kdf|sessionKey|SessionKey|expand)\w*\s*\(`, lines[j])
	not _header_between(lang, lines, j, i)
}

_header_between(lang, lines, j, i) if {
	some k in numbers.range(j + 1, i)
	regex.match(_header_re[lang], lines[k])
}

# The same key is used by another MAC computation of the file.
_key_reused(lang, lines, i, key) if {
	some u in _key_uses(lang, lines)
	u[1] == key
	_other_use(lang, u[0], i)
}

_other_use("py", j, i) if j != i

# In Java the key is bound by the mac.init a few lines above this doFinal.
_other_use("java", j, i) if {
	not _own_init(j, i)
}

_own_init(j, i) if {
	j < i
	j >= i - 6
}

# The challenge came from the peer.
_from_peer(lang, lines, i, v) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[j])
	regex.match(concat("", [`\b`, v, `\b`]), lines[j])
	regex.match(_recv_re, lines[j])
}

_from_peer(lang, lines, i, v) if {
	heads := [j |
		some j in numbers.range(max([0, i - 15]), i)
		regex.match(_header_re[lang], lines[j])
	]
	count(heads) > 0
	m := regex.find_all_string_submatch_n(_header_re[lang], lines[heads[count(heads) - 1]], 1)
	regex.match(concat("", [`\b`, v, `\b`]), m[0][1])
}

# The MAC is handed back to the peer: on this line, or through the name it
# is assigned to within four lines.
_answered(lines, i, line) if regex.match(_sink_re, line)

_answered(lines, i, line) if {
	w := helpers.assigned_first(line)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
	regex.match(concat("", [`\b`, w, `\b`]), lines[k])
	regex.match(_sink_re, lines[k])
	not regex.match(_compare_re, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	contains(content, _gate[lang])
	_verifies(content)
	lines := split(content, "\n")
	_verifies(helpers.code_text(lines))
	some i, line in lines
	contains(line, _gate[lang])
	not helpers.is_comment_line(line)
	not regex.match(_compare_re, line)
	mac := _mac(lang, lines, i, line)
	regex.match(_challenge_name, mac[1])
	_from_peer(lang, lines, i, mac[1])
	_answered(lines, i, line)
	_key_reused(lang, lines, i, mac[0])
	not _enclosing_kdf(lang, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The peer's challenge is answered with the same HMAC, under the same key, that this code expects back for its own challenge, so an attacker can reflect our challenge to us in a second session and replay our answer. Bind the direction into the MAC (the responder's identity or role, different per side) or use a separate key for each direction",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_android_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-ANDROID-004",
	"name": "Android credential stored in plaintext SharedPreferences",
	"description": "A password, token, secret, API/private key, PIN, session id or similar credential is written with putString() to a plain SharedPreferences.Editor, which stores it as cleartext XML under shared_prefs/ (readable on a rooted device, from backups and from device-transfer copies). The editor must be recognisably SharedPreferences: X.edit().putString(...) (also chained across lines), an Editor variable assigned from .edit() or declared SharedPreferences.Editor, or a receiver-less putString inside a Kotlin edit { } / with(prefs.edit()) { } block. The key or the value expression must name the credential (\"auth_token\", KEY_PASSWORD, tokens.accessToken). Not reported: EncryptedSharedPreferences (the preferences object is created by EncryptedSharedPreferences.create, or is named secure/encrypted), values passed through an encrypt/cipher/hash/HMAC call on the same line or assigned from one a few lines above, constant values (\"\", null, literals, R.string resources, used to clear or label), keys that only describe a credential (token_type, token_expiry, password_hint, password_hash, remember_password), push/FCM registration tokens, Bundle/Intent/other key-value stores, comments and strings. Data written through a repository wrapper in another file is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-004/",
	"languages": ["java", "kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [312],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1409"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["android", "shared-preferences", "insecure-storage", "mobile-security"],
}

_lang(path) if endswith(path, ".java")

_lang(path) if endswith(path, ".kt")

_indent(line) := count(line) - count(trim_left(line, " \t"))

# String literals blanked, so a call named inside a string is not a call.
_code(s) := regex.replace(s, `"(\\.|[^"\\])*"`, `""`)

# The text before an occurrence holds an even number of unescaped quotes:
# the occurrence is code, not string content.
_even_quotes(s) if {
	t := regex.replace(s, `\\.`, "")
	count(indexof_n(t, "\"")) % 2 == 0
}

# ── Which SharedPreferences object the editor came from ─────────────────

_root_of(text) := ms[count(ms) - 1][1] if {
	ms := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*(?:\([^()]*\))?\s*\.\s*edit\s*[({]`, text, -1)
	count(ms) > 0
} else := ""

_edit_opener := `\bedit\s*(\([^)]*\))?\s*\{|\.edit\(\)\s*\)\s*\{|\.edit\(\)\s*\.\s*(apply|run|also)\s*\{`

# p is the code before `putString` on line i. Undefined when the receiver is
# not a SharedPreferences.Editor; "" when it is one from an unknown object.
_editor_root(lines, i, p) := r if {
	regex.match(`\.edit\(\)[^;]*\.\s*$`, p)
	r := _root_of(p)
} else := r if {
	ms := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*\.\s*$`, p, 1)
	count(ms) > 0
	r := _editor_var_root(lines, ms[0][1])
} else := r if {
	trim_space(p) == "."
	r := _chain_root(lines, i)
} else := r if {
	not regex.match(`\.\s*$`, p)
	regex.match(`(^|[{;(,\s])$`, p)
	r := _bare_root(lines, i, p)
}

_editor_var_root(lines, r) := root if {
	re := concat("", [`\b`, r, `\s*=\s*[^=;]*\.edit\(\)`])
	assigns := [l | some l in lines; contains(l, r); regex.match(re, l)]
	count(assigns) > 0
	root := _root_of(assigns[0])
} else := "" if {
	re := concat("", [`SharedPreferences\.Editor\s+`, r, `\b|\b`, r, `\s*:\s*SharedPreferences\.Editor`])
	some l in lines
	contains(l, r)
	regex.match(re, l)
} else := "" if regex.match(`(?i)editor$`, r)

# `.putString(...)` continuing a chain that started at `.edit()` above.
_chain_root(lines, i) := r if {
	i > 0
	js := [j | some j in numbers.range(max([0, i - 6]), i - 1); contains(lines[j], ".edit()")]
	count(js) > 0
	j := max(js)
	every l in array.slice(lines, j + 1, i) {
		startswith(trim_space(l), ".")
	}
	r := _root_of(_code(lines[j]))
}

# A receiver-less putString inside an edit { } block: on the same line, or
# the nearest enclosing line above opens one.
_bare_root(lines, i, p) := _root_of(p) if regex.match(_edit_opener, p)

else := r if {
	i > 0
	ind := _indent(lines[i])
	cands := [j |
		some j in numbers.range(max([0, i - 8]), i - 1)
		trim_space(lines[j]) != ""
		not helpers.is_comment_line(lines[j])
		_indent(lines[j]) < ind
	]
	count(cands) > 0
	o := _code(lines[max(cands)])
	regex.match(_edit_opener, o)
	r := _root_of(o)
}

_plain_roots := {"getSharedPreferences", "getDefaultSharedPreferences", "getPreferences"}

_decl_re(r) := concat("", [`\b`, r, `\b\s*(:[^=]*)?(=([^=]|$)|by\b)`])

_declared(lines, r) if {
	r != ""
	some l in lines
	contains(l, r)
	regex.match(_decl_re(r), l)
}

_encrypted_root(_, _, r) if regex.match(`(?i)(encrypt|secure)`, r)

_encrypted_root(lines, _, r) if {
	r != ""
	not r in _plain_roots
	some j, l in lines
	contains(l, r)
	regex.match(_decl_re(r), l)
	contains(helpers.code_window(lines, j, 0, 4), "EncryptedSharedPreferences")
}

_encrypted_root(lines, content, r) if {
	not r in _plain_roots
	contains(content, "EncryptedSharedPreferences")
	not _declared(lines, r)
}

# ── What is stored ───────────────────────────────────────────────────────

_args(argtxt) := [key, value] if {
	ms := regex.find_all_string_submatch_n(`^\s*\(\s*("(?:[^"\\]|\\.)*"|[A-Za-z_][\w.]*(?:\(\))?)\s*,\s*(.*)$`, argtxt, 1)
	count(ms) > 0
	key := ms[0][1]
	vs := regex.find_n(`^(?:[^()]|\((?:[^()]|\([^()]*\))*\))*`, ms[0][2], 1)
	value := trim_space(vs[0])
}

_constant(value) if regex.match(`^("(?:[^"\\]|\\.)*"|null|true|false|-?\d+|R\.string\.\w+|getString\(\s*R\.string\.\w+\s*\))$`, value)

# Names that describe a credential without being one.
_excl := `(?i)((fcm|push|gcm|firebase|messaging|registration|notification|device)_?token|token_?(type|expir\w*|ttl|time|date|scope|count|url|uri|endpoint)|tokeniz\w*|passw(or)?d_?(hint|hash(ed)?|salt|policy|strength|length|rules?|expir\w*|changed|updated|reset|visible|visibility|enabled|required|set)|(has|is|show|use|need|needs|require|forgot|remember|change|reset)_?passw(or)?d|secret_?question)`

_sensitive_re := `(?i)(passw(or)?d|passwd|passphrase|passcode|\bpwd\b|_pwd\b|\bpin\b|_pin\b|pin_?code|secret|api_?key|private_?key|access_?key|auth_?key|token|session_?(id|key|token|cookie)|\bsid\b|cookie|credential|bearer|jwt|\bcvv\b|card_?number)`

# A dotted path (tokens.scope) is judged by its last member: the receiver
# name says what holds the value, not what the value is.
_value_name(value) := value if {
	not regex.match(`^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+$`, value)
} else := v if {
	parts := split(value, ".")
	last := parts[count(parts) - 1]
	last in {"value", "raw", "text", "string"}
	v := concat(".", array.slice(parts, count(parts) - 2, count(parts)))
} else := parts[count(parts) - 1] if parts := split(value, ".")

# A key that only describes a credential (fcm_token) settles the question; the
# value it holds (token) is then not read for a second opinion.
_judged_text(key, value) := key if regex.match(_excl, key)

else := concat(" ", [key, _value_name(value)])

_sensitive(key, value) := m[0] if {
	t := regex.replace(_judged_text(key, value), _excl, " ")
	m := regex.find_n(_sensitive_re, t, 1)
	count(m) > 0
}

_protect_re := `(?i)(encrypt|cipher|hash|digest|\bseal|bcrypt|scrypt|argon|pbkdf|sha\d|hmac|keystore|tink)`

_assigned(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:private|public|protected|internal|final|static|override|lateinit)\s+)*(?:val\s+|var\s+)?(?:[\w.<>\[\]?]+\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w.<>?\[\], ]+)?\s*=[^=]`, line, 1)
	count(m) > 0
}

_protected_value(_, _, value) if regex.match(_protect_re, value)

_protected_value(lines, i, value) if {
	regex.match(`^[A-Za-z_]\w*$`, value)
	i > 0
	some j in numbers.range(max([0, i - 12]), i - 1)
	l := lines[j]
	contains(l, value)
	_assigned(l) == value
	regex.match(_protect_re, l)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "putString")
	contains(content, "edit")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "putString")
	not helpers.is_comment_line(line)
	parts := split(line, "putString")
	some k in numbers.range(1, count(parts) - 1)
	prefix := concat("putString", array.slice(parts, 0, k))
	_even_quotes(prefix)
	not regex.match(`\w$`, prefix)
	regex.match(`^\s*\(`, parts[k])
	root := _editor_root(lines, i, _code(prefix))
	not _encrypted_root(lines, content, root)
	argtxt := concat(" ", array.concat([parts[k]], array.slice(lines, i + 1, min([count(lines), i + 3]))))
	args := _args(argtxt)
	not _constant(args[1])
	what := _sensitive(args[0], args[1])
	not _protected_value(lines, i, args[1])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("A credential (%s) is written to plain SharedPreferences, which stores it as cleartext XML that root access, backups and device transfers can read. Store it in EncryptedSharedPreferences, or encrypt it with a key held in the Android Keystore", [what]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

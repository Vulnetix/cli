package vulnetix.rules.vnx_swift_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SWIFT-003",
	"name": "Swift credential stored in UserDefaults",
	"description": "Reports a Swift write to UserDefaults/NSUserDefaults (set, setValue or setObject on UserDefaults.standard, UserDefaults(suiteName:), NSUserDefaults.standardUserDefaults(), or a variable or property of the file declared as UserDefaults) whose value or key names a credential (or whose value is a dictionary literal with a credential-named key, [\"password\": p]), a SwiftUI @AppStorage property (which is UserDefaults-backed) whose key or property name does, and a SwiftyUserDefaults or sindresorhus Defaults subscript write (Defaults[\\.authToken] = value). A credential is a name ending with password/passwd/pwd/passcode/passphrase, secret, token, apiKey, privateKey, credential(s), pinCode/pin, sessionId, creditCard/cardNumber/cvv or ssn, or a password text field's .text. UserDefaults is an unencrypted plist in the app container that device backups and forensic tools read; credentials belong in the Keychain. Arguments on up to three continuation lines are read. Not reported: booleans, numbers, dates and nil stored under any key, values passed through an encrypt/seal/hash/digest call first, keys that describe rather than hold a credential (hasSeenTokenPrompt, tokenExpiry, passwordAutofillEnabled), reads and removeObject, set(_:forKey:) on receivers that are not UserDefaults (caches, dictionaries), Keychain code, string literals, comment lines and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-003/",
	"languages": ["swift"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [311],
	"capec": ["CAPEC-37"],
	"attack_technique": ["T1409"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["insecure-storage", "swift", "ios"],
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)[^/]*Tests?/`, path)

_is_test(path) if regex.match(`Tests?\.swift$`, path)

_strip(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

_sens_re := `(password|passwd|pwd|passcode|passphrase|secret|token|apikey|api_key|privatekey|private_key|credential|credentials|pincode|pin_code|^pin|[^a-z]pin|sessionid|session_id|creditcard|credit_card|cardnumber|card_number|cvv|ssn)$`

_sensitive_name(n) if regex.match(_sens_re, lower(n))

_last(chain) := parts[count(parts) - 1] if {
	parts := split(regex.replace(chain, `[?!]|\(\)`, ""), ".")
}

_sensitive_value(v) if {
	some m in regex.find_all_string_submatch_n(`[A-Za-z_]\w*(?:[?!]?\.[A-Za-z_]\w*)*`, v, -1)
	_sensitive_name(_last(m[0]))
}

_sensitive_value(v) if regex.match(`(?i)(password|passcode|secret|token|pin)\w*(field|input)[?!]?\.text\b`, v)

_paren_balance(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

_stmt(lines, i) := lines[i] if _paren_balance(_strip(lines[i])) <= 0

_stmt(lines, i) := concat(" ", array.slice(lines, i, min([count(lines), i + 4]))) if _paren_balance(_strip(lines[i])) > 0

# names declared in the file as a UserDefaults instance
_receivers(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`(?:let|var)\s+([A-Za-z_]\w*)\s*(?::\s*(?:NS)?UserDefaults\b|(?::[^=\n]*)?=\s*(?:NS)?UserDefaults\b)`, content, -1)
}

_defaults_receiver(recv, _) if contains(recv, "UserDefaults")

_defaults_receiver(recv, names) if _last(regex.replace(recv, `^self\.`, "")) in names

# the receiver and the argument text of a set call on a stripped statement
_set_call(s) := [m[1], m[2]] if {
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*(?:(?:\([^()]*\))?[?!]?\.[A-Za-z_]\w*)*(?:\([^()]*\))?)[?!]?\.(?:set|setValue|setObject)\s*\((.*)$`, s, -1)
}

_trivial_value(v) if regex.match(`^\s*(true|false|nil|-?\d[\d_.]*|Date\(\)|Date\.now|""|\[\]|\[:\])\s*$`, v)

_stores_secret(raw, args) if {
	parts := split(args, "forKey:")
	count(parts) >= 2
	value := regex.replace(parts[0], `,\s*$`, "")
	not _trivial_value(value)
	not _encrypted_value(value)
	_secret_arg(raw, value, parts[1])
}

# a dictionary literal stored whole: set(["username": u, "password": p], forKey: ...)
_stores_secret(raw, _) if {
	parts := split(raw, "forKey:")
	count(parts) >= 2
	some m in regex.find_all_string_submatch_n(`"([A-Za-z_]\w*)"\s*:`, parts[0], -1)
	_sensitive_name(m[1])
}

# the value is encrypted, sealed or hashed before it is stored
_encrypted_value(v) if regex.match(`^\s*(?:try[?!]?\s+)?(?:[\w.]*\.)?(?i:encrypt|seal|hash|sha\d|digest)\w*\s*\(`, v)

_secret_arg(_, value, _) if _sensitive_value(value)

_secret_arg(raw, _, _) if {
	some m in regex.find_all_string_submatch_n(`forKey:\s*"([^"]*)"`, raw, -1)
	_sensitive_name(m[1])
}

_secret_arg(_, _, key) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_][\w.]*)`, key, 1)
	count(m) > 0
	_sensitive_name(_last(m[0][1]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	contains(content, "UserDefaults")
	names := _receivers(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(set|setValue|setObject)\s*\(`, line)
	not helpers.is_comment_line(line)
	raw := _stmt(lines, i)
	call := _set_call(_strip(raw))
	_defaults_receiver(call[0], names)
	_stores_secret(raw, call[1])
	finding := {
		"rule_id": metadata.id,
		"message": "A credential is written to UserDefaults, an unencrypted plist that backups and forensic tools read; store it in the Keychain (kSecClassGenericPassword with kSecAttrAccessibleWhenUnlockedThisDeviceOnly)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	contains(content, "@AppStorage")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "@AppStorage")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`@AppStorage\s*\(\s*"([^"]*)"[^)]*(?:\([^)]*\))?[^)]*\)\s*(?:(?:private|fileprivate|public|internal)\s+)*var\s+([A-Za-z_]\w*)`, line, 1)
	count(m) > 0
	_app_storage_secret(m[0][1], m[0][2])
	finding := {
		"rule_id": metadata.id,
		"message": "A credential is kept in @AppStorage, which is backed by UserDefaults, an unencrypted plist; store it in the Keychain instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# SwiftyUserDefaults: Defaults[\.authToken] = value / Defaults[.authToken] = value
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	contains(content, "Defaults[")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Defaults[")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])Defaults\[\s*\\?\.([A-Za-z_]\w*)\s*\]\s*=([^=].*)$`, _strip(line), 1)
	count(m) > 0
	_sensitive_name(m[0][1])
	not _trivial_value(m[0][2])
	finding := {
		"rule_id": metadata.id,
		"message": "A credential is written to UserDefaults through SwiftyUserDefaults, an unencrypted plist that backups and forensic tools read; store it in the Keychain instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_app_storage_secret(key, _) if _sensitive_name(key)

_app_storage_secret(_, name) if _sensitive_name(name)

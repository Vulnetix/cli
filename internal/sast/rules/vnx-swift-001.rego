package vulnetix.rules.vnx_swift_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SWIFT-001",
	"name": "Swift hardcoded API key or secret in source",
	"description": "Reports a Swift string literal holding a credential: a let/var declaration (with or without a type annotation and access/static modifiers), a property assignment, a call argument label, a dictionary key (including header-style keys such as \"x-api-key\"), a setValue(_:forHTTPHeaderField:) header, or an == comparison (password == \"...\", passwordTextField.text == \"...\") whose name ends with password/passwd/pwd/passphrase, secret (clientSecret, apiSecret, secretKey, secretAccessKey), apiKey, access/auth/refresh/bearer token, token, privateKey, credential(s) or an encryption/signing/HMAC/master key, given a literal value of at least six characters; and an Authorization-style \"Bearer …\"/\"Basic …\"/\"Token …\" literal with a 16+ character credential. Not reported: letters-only CamelCase identifiers that name a credential (segue, notification and asset names such as \"showPasswordSegue\", \"DeviceTokenRegistered\"), paths beginning with / (\"/oauth2/token\"), masks of one or two repeated characters (\"••••••••\"), values that are placeholders (YOUR_API_KEY_HERE, <client-secret>, ****, xxxx, $(VAR), example/dummy/changeme), interpolated strings, empty or short values, lookup keys rather than values (\"access_token\", \"user_password\", \"com.example.app.token\", \"API_KEY\", \"X-Client-Secret\", a value that is itself the word password/token), prose containing spaces, URLs, names that only describe the value (passwordKey, passwordHint, tokenStorageKey, secretHeader), CodingKeys cases, values read at runtime (Bundle, environment, Keychain), comment lines and test files (XCTest targets, *Tests directories).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-001/",
	"languages": ["swift"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["hardcoded-secrets", "swift", "ios"],
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)[^/]*Tests?/`, path)

_is_test(path) if regex.match(`Tests?\.swift$`, path)

_str := `"((?:[^"\\]|\\.)*)"`

_decl_re := concat("", [`^\s*(?:@\w+\s+)*(?:(?:private|fileprivate|public|internal|open|static|final|lazy|nonisolated|override|class)(?:\(set\))?\s+)*(?:let|var)\s+([A-Za-z_]\w*)\s*(?::\s*[\w.?!<>\[\]]+\s*)?=\s*`, _str])

_assign_re := concat("", [`^\s*(?:[\w.]+\.)?([A-Za-z_]\w*)\s*=\s*`, _str])

_label_re := concat("", [`(?:^|[(,\[])\s*"?([A-Za-z_]\w*)"?\s*:\s*`, _str])

# the identifier must END with the credential word: apiKey, clientSecret,
# CookiePassword, VVD_SECRET; passwordKey, passwordHint, tokenStorageKey do not.
_name_re := `(password|passwd|passphrase|pwd|secret|secretkey|secret_key|apikey|api_key|secretaccesskey|secret_access_key|token|privatekey|private_key|credential|credentials|encryptionkey|encryption_key|signingkey|signing_key|hmackey|hmac_key|masterkey|master_key)$`

# a quoted header-style dictionary key: ["x-api-key": "..."]
_dash_key_re := concat("", [`"([A-Za-z][\w\-]*-[\w\-]*)"\s*:\s*`, _str])

# a comparison with a literal: password == "...", passwordTextField.text == "..."
_cmp_re := concat("", [`([A-Za-z_]\w*)(?:\.text)?[?!]?\s*==\s*`, _str])

# request.setValue("...", forHTTPHeaderField: "X-Api-Key")
_header_re := concat("", [`setValue\(\s*`, _str, `\s*,\s*forHTTPHeaderField:\s*"([^"]+)"`])

_norm(n) := regex.replace(regex.replace(n, `-`, "_"), `(?i)(Text)?(Field|Input)$`, "")

_pairs(line) := {[_norm(m[1]), m[2]] |
	some re in [_decl_re, _assign_re, _label_re, _dash_key_re, _cmp_re]
	some m in regex.find_all_string_submatch_n(re, line, -1)
} | {[_norm(m[2]), m[1]] | some m in regex.find_all_string_submatch_n(_header_re, line, -1)}

_placeholder_re := `(?i)(your|_here|here_|example|changeme|change_me|placeholder|dummy|sample|todo|replace|redacted|xxx|\*\*\*|\.\.\.|^<.*>$|\$\(|\$\{|\{\{|%@|%s|%d)`

_secret_value(v) if {
	count(v) >= 6
	not contains(v, `\(`)
	not regex.match(`\s`, v)
	not contains(v, "://")
	not regex.match(_placeholder_re, v)
	not regex.match(`^[a-z]+([_.\-][a-z]+)+$`, v)
	not regex.match(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`, v)
	not regex.match(`^[A-Z][A-Za-z]*(-[A-Z][A-Za-z]*)+$`, v)
	not regex.match(concat("", ["^", _name_re]), lower(v))
	count({c | some c in split(v, "")}) > 2
	not startswith(v, "/")
	not _identifier_value(v)
}

# a CamelCase identifier that names a credential: a segue, notification,
# asset or storyboard name ("showPasswordSegue", "DeviceTokenRegistered")
_identifier_value(v) if {
	regex.match(`^[A-Za-z]+$`, v)
	regex.match(`[a-z][A-Z]`, v)
	regex.match(`(?i)(password|passwd|passcode|secret|token|key|credential|pin)`, v)
}

_hit(line) if {
	some p in _pairs(line)
	regex.match(_name_re, lower(p[0]))
	_secret_value(p[1])
}

_hit(line) if regex.match(`"(?:Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=\-]{16,}"`, line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	regex.match(`(?i)(pass|pwd|secret|key|token|credential|bearer|basic )`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "\"")
	regex.match(`(?i)(pass|pwd|secret|key|token|credential|bearer|basic )`, line)
	not helpers.is_comment_line(line)
	_hit(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardcoded secret in Swift source; store credentials in the Keychain or fetch them from a server at runtime, and rotate this value, which anyone with the binary can extract",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

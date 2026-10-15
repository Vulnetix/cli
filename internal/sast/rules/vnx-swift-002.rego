package vulnetix.rules.vnx_swift_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SWIFT-002",
	"name": "Swift credential written to the device log (NSLog, print, public os_log/Logger)",
	"description": "Reports a Swift NSLog, print, debugPrint, dump or CocoaLumberjack DDLogVerbose/DDLogDebug/DDLogInfo/DDLogWarn/DDLogError call that passes a credential value as an argument or interpolates it into the message, an os_log call whose format marks an argument %{public} and passes one, and a Logger (os.Logger) call that interpolates one with privacy: .public. A credential value is an identifier or the last member of a property chain whose name ends with password/passwd/pwd/passcode/passphrase, secret, token, apiKey, privateKey or credential(s), a password text field's .text, or a local variable assigned from one in the six lines above. Arguments on up to three continuation lines are read. Not reported: the sensitive word inside the message text alone (\"wrong password\"), names that describe rather than hold the value (hashedPassword, maskedToken, tokenType, tokenExpiry, passwordPolicy, credentials.username), a value compared with nil, its .count/.isEmpty, or a value passed through mask/redact/hash/sanitize, os_log without %{public} and Logger interpolations without privacy: .public (both are redacted by default), comment lines and test files. Overlaps VNX-SEC-022 for NSLog/print; this rule adds the unified-logging privacy semantics.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-002/",
	"languages": ["swift"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [532],
	"capec": ["CAPEC-215"],
	"attack_technique": ["T1552"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["logging", "sensitive-data", "swift", "ios"],
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)[^/]*Tests?/`, path)

_is_test(path) if regex.match(`Tests?\.swift$`, path)

_str_re := `"(?:[^"\\]|\\.)*"`

_strip(l) := regex.replace(l, _str_re, `""`)

_interp_re := `\\\(((?:[^()]|\([^()]*\))*)\)`

_sens_re := `(password|passwd|pwd|passcode|passphrase|secret|token|apikey|api_key|privatekey|private_key|credential|credentials)$`

_field_re := `(password|passwd|passcode|secret|token|apikey|pin)(text)?(field|textfield|input)$`

# kind of log call on the (string-stripped) line, and the text after it
_call(s) := ["plain", m[0][2]] if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])(NSLog|print|debugPrint|dump|DDLog(?:Verbose|Debug|Info|Warn|Error))\s*\((.*)$`, s, 1)
	count(m) > 0
}

_call(s) := ["oslog", m[0][1]] if {
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])os_log\s*\((.*)$`, s, 1)
	count(m) > 0
}

_call(s) := ["logger", m[0][2]] if {
	not regex.match(`(?:^|[^\w.])(NSLog|print|debugPrint|dump|DDLog(?:Verbose|Debug|Info|Warn|Error)|os_log)\s*\(`, s)
	m := regex.find_all_string_submatch_n(`(?i:\w*logger|\blog)(?:\(\))?\.(trace|debug|info|notice|warning|error|critical|fault|log)\s*\((.*)$`, s, 1)
	count(m) > 0
}

_paren_balance(s) := count(regex.find_all_string_submatch_n(`\(`, s, -1)) - count(regex.find_all_string_submatch_n(`\)`, s, -1))

# the statement: the line plus continuation lines while parentheses are open
_stmt(lines, i) := lines[i] if _paren_balance(_strip(lines[i])) <= 0

_stmt(lines, i) := concat(" ", array.slice(lines, i, min([count(lines), i + 4]))) if _paren_balance(_strip(lines[i])) > 0

_first_expr(e) := trim_space(split(e, ",")[0])

# expressions the call logs, by call kind
_exprs("plain", raw, rest) := array.concat([rest], [_first_expr(m[1]) | some m in regex.find_all_string_submatch_n(_interp_re, raw, -1)])

_exprs("oslog", raw, rest) := [rest] if contains(raw, "%{public}")

_exprs("logger", raw, _) := [_first_expr(m[1]) |
	some m in regex.find_all_string_submatch_n(_interp_re, raw, -1)
	regex.match(`privacy:\s*\.public\b`, m[1])
]

_chain_re := `((?i:mask|redact|hash|sha\d*|obfuscat\w*|sanitiz\w*|digest|truncat\w*)\w*\(\s*)?([A-Za-z_]\w*(?:[?!]?\.[A-Za-z_]\w*)*)(\s*[!=]=\s*nil)?`

_sensitive_chain(c, _) if {
	parts := split(regex.replace(c, `[?!]`, ""), ".")
	last := lower(parts[count(parts) - 1])
	regex.match(_sens_re, last)
	not regex.match(`^(hashed|masked|redacted|obfuscated)`, last)
}

_sensitive_chain(c, _) if {
	parts := split(regex.replace(c, `[?!]`, ""), ".")
	count(parts) >= 2
	parts[count(parts) - 1] == "text"
	regex.match(_field_re, lower(parts[count(parts) - 2]))
}

_sensitive_chain(c, tainted) if c in tainted

_logs_secret(exprs, tainted) if {
	some e in exprs
	some m in regex.find_all_string_submatch_n(_chain_re, e, -1)
	m[1] == ""
	m[3] == ""
	_sensitive_chain(m[2], tainted)
}

# locals assigned from a credential value a few lines above
_tainted(lines, i) := {m[1] |
	some j in numbers.range(max([0, i - 6]), i - 1)
	not helpers.is_comment_line(lines[j])
	m := regex.find_all_string_submatch_n(`^\s*(?:let|var)\s+([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(.+)$`, _strip(lines[j]), 1)[0]
	_logs_secret([m[2]], set())
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	regex.match(`(NSLog|print|debugPrint|dump|DDLog(?:Verbose|Debug|Info|Warn|Error)|os_log|\.(trace|debug|info|notice|warning|error|critical|fault|log))\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(NSLog|print|debugPrint|dump|DDLog(?:Verbose|Debug|Info|Warn|Error)|os_log|\.(trace|debug|info|notice|warning|error|critical|fault|log))\s*\(`, line)
	not helpers.is_comment_line(line)
	raw := _stmt(lines, i)
	c := _call(_strip(raw))
	exprs := _exprs(c[0], raw, c[1])
	_logs_secret(exprs, _tainted(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "A credential is written to the device log; remove it from the log call, or log through os.Logger without privacy: .public so the value is redacted",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_257

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-257",
	"name": "Storing Passwords in a Recoverable Format",
	"description": "A password is encoded or encrypted instead of hashed, so whoever holds the stored value (or the key) gets the password back. Reported when the first argument (the data, not the key) of a reversible transform is a password-named expression (password, passwd, pwd, passphrase, newPassword, user.password, $_POST['password'], getPassword(), with .encode()/.getBytes()/[]byte() around it), written on the call's line, alone on the line after the opening parenthesis, or as a variable assigned from such an expression up to five lines above (data = user_password.encode(); fernet.encrypt(data)): Python base64.b64encode/urlsafe_b64encode/b32encode/encodebytes, binascii.hexlify, codecs.encode, an .encrypt(...) call (Fernet, AES, any cipher); JavaScript btoa, Buffer.from(...).toString('base64'|'hex'), CryptoJS.AES/DES/TripleDES/RC4/Rabbit.encrypt, cipher.update; Java Base64.getEncoder().encode/encodeToString, cipher.doFinal, .encrypt; PHP base64_encode, openssl_encrypt, str_rot13; Ruby Base64.encode64/strict_encode64/urlsafe_encode64; Go base64.*.EncodeToString, hex.EncodeToString and AEAD Seal of the password as plaintext. Also reported: a function named decrypt_password/decryptPassword/DecryptPassword, defined or called, which exists only because passwords are stored recoverably. Not reported: HTTP Basic credentials (a line building user:password or naming Basic), a password used as the key or the input of a key-derivation function (pbkdf2, scrypt, argon2, PBEKeySpec, including Buffer.from(password) inside scryptSync(...).toString('hex')), outbound credentials this system must present to another one and so has to keep recoverable (smtp_password, db_password, ldap_bind_password, proxy, API, keystore and vault passwords), encoding of a hash, salt or digest (password_hash, passwordHash), names that only contain the word (passwordFieldId), comments, strings and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-257/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [257],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["password-recovery", "reversible", "cwe-257"],
}

_code_file(path) if regex.match(`\.(py|js|jsx|ts|tsx|mjs|cjs|java|php|rb|go)$`, path)

# A reversible transform, ending where its data argument begins.
_sink := concat("|", [
	`\bbase64\.(?:b64encode|urlsafe_b64encode|standard_b64encode|encodebytes|b32encode)\(\s*`,
	`\bbinascii\.hexlify\(\s*`,
	`\bcodecs\.encode\(\s*`,
	`\bbtoa\(\s*`,
	`\bBuffer\.from\(\s*`,
	`\bCryptoJS\.(?:AES|DES|TripleDES|Rabbit|RC4|RC4Drop)\.encrypt\(\s*`,
	`\.encrypt\(\s*`,
	`\b\w*[cC]ipher\w*\.(?:update|doFinal)\(\s*`,
	`\bBase64\.(?:getEncoder|getMimeEncoder|getUrlEncoder)\(\)\.encode(?:ToString)?\(\s*`,
	`\b(?:base64_encode|openssl_encrypt|str_rot13|bin2hex)\(\s*`,
	`\bBase64\.(?:encode64|strict_encode64|urlsafe_encode64)\(?\s*`,
	`\bbase64\.(?:StdEncoding|URLEncoding|RawStdEncoding|RawURLEncoding)\.EncodeToString\(\s*`,
	`\bhex\.EncodeToString\(\s*`,
	`\.Seal\(\s*[^,]+,\s*[^,]+,\s*`,
])

# The data argument: an identifier chain, optionally wrapped in []byte(...)
# or pad(...), optionally followed by .encode()/.getBytes(...).
_chain := `((?:\[\]byte\(\s*|pad\(\s*|bytes\(\s*|str\(\s*)?\$?[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*(?:\(\))?|\[\s*['":]?\w+['"]?\s*\])*)`

_arg_re := concat("", [`(?:`, _sink, `)`, _chain])

_password_name := `(?i)(?:password|passwd|pwd|passphrase)(?:\(\))?['"]?\s*\]?$`

_basic(line) if regex.match(`(?i)\bbasic\b|["'\x60]\s*:\s*["'\x60]|:\$\{|\}:\$|\+\s*["']:["']\s*\+`, line)

# Buffer.from(x) is only an encoding when it is turned into base64 or hex.
_buffer_ok(line, m) if not startswith(trim_space(m), "Buffer.from")

_buffer_ok(line, m) if {
	startswith(trim_space(m), "Buffer.from")
	regex.match(`toString\(\s*['"](?:base64|hex|base64url)['"]`, line)
	not regex.match(`(?i)scrypt|pbkdf2|argon2|bcrypt|hkdf|createHash|createHmac|digest`, line)
}

# The password-named expression, with .encode()/.getBytes() removed.
_stripped(chain) := regex.replace(chain, `(?:\.(?:encode|getBytes|toCharArray|bytes|to_s|as_bytes|trim|strip)(?:\(\))?)+$`, "")

_is_password(chain) if {
	s := _stripped(chain)
	regex.match(_password_name, s)
	not _outbound(s)
}

# A credential this system presents to another one (SMTP, a database, LDAP,
# a proxy) has to be recoverable; encrypting it is correct.
_outbound(s) if regex.match(`(?i)(?:smtp|mail|email|db|database|ftp|sftp|ldap|bind|proxy|redis|mq|amqp|broker|wifi|wlan|keystore|truststore|vault|api|remote|integration|service|upstream|registry|git|imap|pop3?|sql|mysql|postgres|mongo)_?pass(?:word|wd|phrase)?\W*$`, s)
_in_string(line, idx) if {
	before := substring(line, 0, idx)
	q := count(regex.find_all_string_submatch_n(`["']`, before, -1))
	q % 2 == 1
}

_pw_word := `(?i)pass(?:w|phrase)|pwd`

# One pass over the lines that name a password: the sink on that line, the
# sink a few lines below taking a variable assigned on it, or the sink opened
# on the line above with the password as its argument on this one.
findings contains finding if {
	some path, content in input.file_contents
	_code_file(path)
	not helpers.is_test_path(path)
	regex.match(_pw_word, content)
	lines := split(content, "\n")
	some k, line in lines
	regex.match(_pw_word, line)
	not helpers.is_comment_line(line)
	some r in _hits(lines, k, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r + 1,
		"snippet": lines[r],
	}
}

_hits(lines, k, line) := ({r | r := k; _direct(line)} | _hop(lines, k, line)) | {r | r := k; _multi(lines, k, line)}

_direct(line) if {
	contains(line, "(")
	not _basic(line)
	some m in regex.find_all_string_submatch_n(_arg_re, line, -1)
	_is_password(m[1])
	_buffer_ok(line, m[0])
	not _in_string(line, indexof(line, m[0]))
}

_message := "Password encoded or encrypted into a recoverable form; store a salted hash from bcrypt/argon2/scrypt/PBKDF2 instead, and use a reset flow rather than recovery"

# Two-line form: `data = user_password.encode()`, then the sink takes `data`
# within the next five lines.
_pw_assign := concat("", [`^\s*(?:(?:const|let|var|final|byte\s*\[\s*\]|String|bytes)\s+)?\$?(\w+)\s*:?=\s*`, _chain, `(?:\([^()]*\))?\s*;?\s*$`])

_var_sink(v) := concat("", [`(?:`, _sink, `)(?:\[\]byte\(\s*)?\$?`, v, `\s*[,)]`])

_hop(lines, k, aline) := {i |
	contains(aline, "=")
	m := regex.find_all_string_submatch_n(_pw_assign, aline, 1)
	count(m) > 0
	v := m[0][1]
	not regex.match(_pw_word, v)
	_is_password(m[0][2])
	some i in numbers.range(k + 1, min([count(lines) - 1, k + 5]))
	line := lines[i]
	contains(line, v)
	not helpers.is_comment_line(line)
	not _basic(line)
	some sm in regex.find_all_string_submatch_n(_var_sink(v), line, -1)
	_buffer_ok(line, sm[0])
	not _in_string(line, indexof(line, sm[0]))
}

# The password argument alone on the line after `encrypt(` / `b64encode(`.
_multi(lines, k, line) if {
	k > 0
	endswith(trim_space(lines[k - 1]), "(")
	regex.match(concat("", [`(?:`, _sink, `)$`]), lines[k - 1])
	not startswith(trim_space(lines[k - 1]), "Buffer.from")
	nm := regex.find_all_string_submatch_n(concat("", [`^\s*`, _chain]), line, 1)
	count(nm) > 0
	_is_password(nm[0][1])
}

_decrypt_re := `\b(?:decrypt_?[Pp]assword|DecryptPassword|decrypt_pass|decryptPwd)\s*\(|^\s*def\s+(?:self\.)?decrypt_?[Pp]assword\b`

findings contains finding if {
	some path, content in input.file_contents
	_code_file(path)
	not helpers.is_test_path(path)
	regex.match(`(?i)decrypt_?(?:password|pass|pwd)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_decrypt_re, line)
	not helpers.is_comment_line(line)
	not _in_string(line, indexof(line, regex.find_n(_decrypt_re, line, 1)[0]))
	finding := {
		"rule_id": metadata.id,
		"message": "Password decryption: passwords are stored in a recoverable format; store a salted hash and use a reset flow instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

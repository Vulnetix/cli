# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_261

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-261",
	"name": "Weak Encoding for Password",
	"description": "A password is passed straight to a reversible encoding: base64 (Python base64.b64encode/urlsafe_b64encode/encodebytes, JavaScript btoa() and Buffer.from(...).toString('base64'|'hex'), including a Buffer.from( call broken across lines, Java Base64.getEncoder().encodeToString/encode, DatatypeConverter.printBase64Binary/printHexBinary, HexFormat.formatHex, commons-codec encodeBase64String/encodeHexString, Go base64.*Encoding.EncodeToString and hex.EncodeToString, PHP base64_encode/bin2hex, Ruby Base64.encode64/strict_encode64/urlsafe_encode64), hex (binascii.hexlify) or ROT13 (codecs.encode(..., 'rot13'), str_rot13). The argument names a password (an identifier ending in password, passwd, pwd or passphrase, or a password field of a request) directly, or through a variable assigned from one in the six lines above. Anyone who reads the stored or logged value can decode it. Not reported: HTTP Basic credentials (a user:password join, or an Authorization/Basic header on the line), a password that is hashed, derived, signed or encrypted before it is encoded, decoding, lookalike names (passwordHash, password_reset_token, compass), and the calls in comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-261/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [261],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "encoding", "cwe-261"],
}

_exts := {".py", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".php", ".rb"}

# Cheap whole-file gate: an encoder name appears somewhere in the file.
_gate_re := `formatHex|b64encode|encodebytes|encodestring|b2a_base64|hexlify|btoa|ncodeToString|printBase64Binary|printHexBinary|encodeBase64|encodeHex|base64_encode|str_rot13|bin2hex|encode64|BASE64Encoder|Encoder\(\)\.encode|toString\(\s*['"](base64|hex)|rot.?13`

# Encoder call; group 1 is the rest of the line after its opening parenthesis.
_enc_re := `(?:\bformatHex|\b(?:urlsafe_|standard_)?b64encode|\bencodebytes|\bencodestring|\bb2a_base64|\bhexlify|\bbtoa|\b[Ee]ncodeToString|\bprintBase64Binary|\bprintHexBinary|\bencodeBase64(?:String|URLSafeString|URLSafe|Chunked)?|\bencodeHexString|\bencodeHex|\bbase64_encode|\bstr_rot13|\bbin2hex|\bconvert_uuencode|\b(?:strict_|urlsafe_)?encode64|BASE64Encoder\(\)\.encode(?:Buffer)?|get(?:Url|Mime)?Encoder\(\)\.encode)\s*\((.*)$`

_rot13_re := `\bcodecs\.encode\s*\((.*rot.?13.*)$`

# Buffer.from(<arg>).toString('base64'): the argument comes before the encoder.
_buf_re := `(?:Buffer\.from|new\s+Buffer)\s*\(((?:[^()]|\([^()]*\))*)\)\s*\.toString\(\s*['"](?:base64|base64url|hex)['"]`

# A password-named value: an identifier ending in password/passwd/pwd/passphrase
# (userPassword, new_password, getPassword(), $_POST['password']).
_pw_re := `(?i)[A-Za-z0-9_]*(password|passwd|pwd|passphrase)\b`

# Hashed, derived, signed or encrypted before encoding: the encoding is of a digest.
_crypto_re := `(?i)hash|digest|crypt|hmac|encoder\.encode|pbkdf|scrypt|argon|sign|cipher|doFinal|sha\d|md5|kdf|derive|salt`

# A user:password join is an HTTP Basic credential, which the protocol encodes.
_basic_re := `":"|':'|b":"|:\$|:\{|:#\{|%s:%s|Authorization|Basic\b`

# The encoder is called in code, not named inside a string literal.
_call_gate_re := `(formatHex|b64encode|encodebytes|encodestring|b2a_base64|hexlify|btoa|ncodeToString|printBase64Binary|printHexBinary|encodeBase64\w*|encodeHex\w*|base64_encode|str_rot13|bin2hex|convert_uuencode|encode64|Encoder\(\)\.encode\w*|codecs\.encode)\s*\(|\.toString\(\s*''`

# String literals blanked, so a quoted example is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_arg_enc(lines, i, line) := a if {
	m := regex.find_all_string_submatch_n(_enc_re, line, 1)
	count(m) > 0
	a := _with_next(lines, i, m[0][1])
}

_arg_rot(line) := a if {
	m := regex.find_all_string_submatch_n(_rot13_re, line, 1)
	count(m) > 0
	a := m[0][1]
}

_arg_buf(line) := a if {
	m := regex.find_all_string_submatch_n(_buf_re, line, 1)
	count(m) > 0
	a := m[0][1]
}

# A call broken after its opening parenthesis takes its argument from the next line.
_with_next(lines, i, rest) := rest if trim_space(rest) != ""

_with_next(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

_password_arg(_, _, arg) if regex.match(_pw_re, arg)

# Two-line form: a variable assigned from a password in the six lines above.
_password_arg(lines, i, arg) if {
	i > 0
	some j in numbers.range(max([0, i - 6]), i - 1)
	prev := lines[j]
	regex.match(_pw_re, prev)
	not helpers.is_comment_line(prev)
	not regex.match(_crypto_re, prev)
	not regex.match(_basic_re, prev)
	v := helpers.assigned_ident(prev)
	not regex.match(_pw_re, v)
	regex.match(concat("", [`\b`, v, `\b`]), arg)
}

# Substring tests, cheaper than a case-insensitive regex over every file.
_mentions_password(content) if {
	some n in {"assw", "ASSW", "pwd", "Pwd", "PWD", "assphrase"}
	contains(content, n)
}

_encoder_word(line) if {
	some n in {"ncode", "formatHex", "btoa", "hexlify", "bin2hex", "rot13", "toString", "printBase64", "printHex", "b2a_"}
	contains(line, n)
}

# Buffer.from( broken across lines (prettier style): the argument is on the
# next lines and ).toString('base64') closes the call within four lines.
_buf_open_re := `(?:Buffer\.from|new\s+Buffer)\s*\(\s*$`

_buf_close_re := `^\s*(?:\S.*)?\)\s*\.toString\(\s*['"](?:base64|base64url|hex)['"]`

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
	contains(content, "Buffer")
	_mentions_password(content)
	regex.match(`(?m)(?:Buffer\.from|new\s+Buffer)\s*\(\s*$`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_buf_open_re, line)
	not helpers.is_comment_line(line)
	some k in numbers.range(i + 1, min([i + 4, count(lines) - 1]))
	regex.match(_buf_close_re, lines[k])
	arg := concat(" ", array.slice(lines, i + 1, k + 1))
	not regex.match(_crypto_re, arg)
	not regex.match(_basic_re, arg)
	_password_arg(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Password stored or emitted with a reversible encoding (base64/hex/ROT13): anyone who reads the value can decode it. Hash passwords with bcrypt, scrypt, Argon2 or PBKDF2, or encrypt them with a managed key if they must be recovered",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	_mentions_password(content)
	_encoder_word(content)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	_encoder_word(line)
	regex.match(_gate_re, line)
	not helpers.is_comment_line(line)
	regex.match(_call_gate_re, _code(line))
	not regex.match(_basic_re, line)
	args := ({a | a := _arg_enc(lines, i, line)} | {a | a := _arg_rot(line)}) | {a | a := _arg_buf(line)}
	some arg in args
	not regex.match(_crypto_re, arg)
	_password_arg(lines, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Password stored or emitted with a reversible encoding (base64/hex/ROT13): anyone who reads the value can decode it. Hash passwords with bcrypt, scrypt, Argon2 or PBKDF2, or encrypt them with a managed key if they must be recovered",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

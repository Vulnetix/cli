package vulnetix.rules.vnx_php_019

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-019",
	"name": "PHP insecure cipher mode (AES-CBC)",
	"description": "openssl_encrypt() or openssl_decrypt() is called with an unauthenticated CBC block cipher (aes/aria/camellia-128/192/256-cbc, or the OpenSSL alias aes128/aes192/aes256) as its method, given literally or through a variable, property, class constant or define() assigned that literal in the same file, or mcrypt_encrypt()/mcrypt_decrypt() is called with MCRYPT_MODE_CBC or 'cbc', in a file that computes no HMAC. Without a MAC, CBC ciphertext can be modified undetected (bit flipping) and decryption errors become a padding oracle. Not reported: AEAD methods (aes-*-gcm, chacha20-poly1305), OpenSSL's composite aes-*-cbc-hmac-* methods, files that also call hash_hmac() (encrypt-then-MAC, as Laravel's Encrypter does), a cipher name in a configuration array with no encrypt call, a method whose value is not visible in the file, comments and string literals. ECB mode and DES/RC4 are other rules' concern.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-019/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["weak-crypto", "cipher", "php"],
}

# One call argument: literals, one level of nested parentheses/brackets, or
# anything else up to the next comma.
_arg := `(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\((?:[^()'"]|'[^']*'|"[^"]*"|\([^()]*\))*\)|\[[^\[\]]*\]|[^,'"()\[\]])+`

_cbc_lit := `(?i:(?:aes|aria|camellia)-(?:128|192|256)-cbc|aes(?:128|192|256))`

_openssl_re := concat("", [`openssl_(?:en|de)crypt\s*\(\s*`, _arg, `\s*,\s*(`, _arg, `)`])

_mcrypt_re := concat("", [`mcrypt_(?:en|de)crypt\s*\(\s*`, _arg, `\s*,\s*`, _arg, `\s*,\s*`, _arg, `\s*,\s*(`, _arg, `)`])

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_stmt(lines, i, from) := s if {
	end := min([count(lines) - 1, i + 8])
	joined := concat(" ", array.slice(lines, i, end + 1))
	tail := substring(joined, indexof(joined, from), -1)
	s := split(tail, ";")[0]
}

_is_cbc_literal(a) if regex.match(concat("", [`^['"]`, _cbc_lit, `['"]$`]), a)

_lit_value := concat("", [`\s*=\s*['"]`, _cbc_lit, `['"]`])

# The method's value, resolved within the file.
_cbc(_, a) if _is_cbc_literal(a)

_cbc(content, a) if {
	m := regex.find_all_string_submatch_n(`^\$(?:this->)?(\w+)$`, a, 1)
	count(m) > 0
	regex.match(concat("", [`(?m)\$`, m[0][1], _lit_value]), content)
}

_cbc(content, a) if {
	m := regex.find_all_string_submatch_n(`^(?:(?:self|static|\\?\w+)::)?([A-Z_][A-Z0-9_]*)$`, a, 1)
	count(m) > 0
	name := m[0][1]
	regex.match(concat("", [`(?m)\bconst\s+`, name, _lit_value, `|define\s*\(\s*['"]`, name, `['"]\s*,\s*['"]`, _cbc_lit, `['"]`]), content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`openssl_(en|de)crypt\s*\(`, content)
	regex.match(concat("", [`['"]`, _cbc_lit, `['"]`]), content)
	not regex.match(`hash_hmac\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "openssl_")
	not helpers.is_comment_line(line)
	regex.match(`(^|[^\w$>:])\\?openssl_(en|de)crypt\s*\(`, _no_strings(line))
	stmt := _stmt(lines, i, "openssl_")
	m := regex.find_all_string_submatch_n(_openssl_re, stmt, 1)
	count(m) > 0
	_cbc(content, trim_space(m[0][1]))
	finding := {
		"rule_id": metadata.id,
		"message": "openssl_encrypt()/openssl_decrypt() uses an unauthenticated CBC cipher with no HMAC in this file: ciphertext can be tampered with and padding errors leak plaintext; use aes-256-gcm (keep the tag) or add encrypt-then-MAC with hash_hmac()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`mcrypt_(en|de)crypt\s*\(`, content)
	not regex.match(`hash_hmac\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "mcrypt_")
	not helpers.is_comment_line(line)
	regex.match(`(^|[^\w$>:])\\?mcrypt_(en|de)crypt\s*\(`, _no_strings(line))
	stmt := _stmt(lines, i, "mcrypt_")
	m := regex.find_all_string_submatch_n(_mcrypt_re, stmt, 1)
	count(m) > 0
	regex.match(`^(MCRYPT_MODE_CBC|['"](?i:cbc)['"])$`, trim_space(m[0][1]))
	finding := {
		"rule_id": metadata.id,
		"message": "mcrypt CBC encryption with no HMAC in this file: ciphertext can be tampered with and padding errors leak plaintext; migrate to openssl_encrypt() with aes-256-gcm or sodium_crypto_secretbox()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

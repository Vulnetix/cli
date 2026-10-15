package vulnetix.rules.vnx_crypto_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-003",
	"name": "AES in ECB mode",
	"description": "A block cipher (AES, and any other cipher named the same way) is set up in ECB mode: Python AES.new(key, AES.MODE_ECB) or any MODE_ECB argument, cryptography modes.ECB(), pyaes AESModeOfOperationECB and the legacy PyCrypto AES.new(key) whose default mode is ECB; Node.js crypto.createCipheriv/createDecipheriv/createCipher with an '*-ecb' cipher name (literally or through a constant assigned it), CryptoJS mode.ECB and aes-js ModeOfOperation.ecb; Go NewECBEncrypter/NewECBDecrypter and a cipher.Block's Encrypt/Decrypt called on successive slices inside a loop (ECB written by hand); Java Cipher.getInstance with an '*/ECB/*' transformation or with a bare \"AES\", \"DES\", \"DESede\" or \"Blowfish\" transformation, whose provider default is ECB with PKCS5 padding, given literally, through a variable or constant, or as a getProperty default; Ruby OpenSSL::Cipher.new('aes-*-ecb') and OpenSSL::Cipher::AES.new(n, :ECB); PHP openssl_encrypt/openssl_decrypt with an '*-ecb' method (literal or variable), mcrypt MCRYPT_MODE_ECB/mcrypt_ecb() and phpseclib MODE_ECB or new AES('ecb'). ECB encrypts equal plaintext blocks to equal ciphertext blocks and carries no integrity, so tokens and records leak structure and can be cut and pasted; use AES-GCM (or ChaCha20-Poly1305). Not reported: GCM, CBC, CTR and other modes, RSA/ECB/* transformations (an RSA cipher has no block mode; padding is another rule's concern), AESWrap and AES/KW, a comparison against MODE_ECB (a guard rejecting it), a cipher name in a deny-list, KeyGenerator/SecretKeySpec with \"AES\" (a key, not a mode), a single-block Encrypt outside a loop (CMAC subkeys, key wrapping), ECB named inside a string literal, prose or a comment, documentation, and test files (known-answer vectors are ECB by definition).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-003/",
	"languages": ["python", "node", "go", "java", "ruby", "php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["weak-crypto", "ecb", "aes", "block-cipher"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if {
	regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)
	not endswith(path, ".min.js")
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "ruby" if endswith(path, ".rb")

_lang(path) := "php" if endswith(path, ".php")

# A cipher-name literal in ECB mode ('aes-128-ecb', "AES/ECB/PKCS5Padding",
# 'des-ede3-ecb', 'ecb') becomes a sentinel before string literals are
# blanked, so the call that names it is still recognisable while the same
# text inside a longer string (a warning, prose) is not.
_ecb_lit := "['\"`](?i:[a-z0-9]+(?:-[a-z0-9]+)*-ecb|[a-z0-9]+/ecb(?:/[a-z0-9]+)?|ecb)['\"`]"

# Java: a bare "AES" transformation, which providers expand to AES/ECB.
_aes_default_lit := `"(?i:aes(?:_(?:128|192|256))?|des|desede|tripledes|blowfish)"`

_strings := {
	"python": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"node": "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`",
	"go": "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`",
	"java": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"ruby": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"php": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
}

_tail_comment := {
	"python": `#.*$`,
	"node": `//.*$`,
	"go": `//.*$`,
	"java": `//.*$`,
	"ruby": `#.*$`,
	"php": `(?://|#).*$`,
}

_code(lang, line) := c if {
	# RSA/ECB/... names no block mode: an RSA cipher encrypts one block
	s0 := regex.replace(line, `(?i)['"](?:rsa|ecies|elgamal)/ecb/[^'"]*['"]`, `""`)
	s := regex.replace(s0, _ecb_lit, "__ECB__")
	s2 := _java_default(lang, s)
	t := regex.replace(s2, _strings[lang], `""`)
	c := regex.replace(t, _tail_comment[lang], "")
}

_java_default("java", s) := regex.replace(s, _aes_default_lit, "__AESDEF__")

_java_default(lang, s) := s if lang != "java"

_static := {
	"python": [
		`MODE_ECB\b`,
		`\bmodes\.ECB\s*\(`,
		`\bAESModeOfOperationECB\s*\(`,
		`\bAES\.new\s*\(\s*[^,()]+\)`,
	],
	"node": [
		`\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*__ECB__`,
		`\bCryptoJS\.mode\.ECB\b`,
		`\bModeOfOperation\.ecb\b`,
	],
	"go": [`\bNewECB(?:En|De)crypter\s*\(`],
	"java": [`\bCipher\.getInstance\s*\(\s*(?:__ECB__|__AESDEF__)`],
	"ruby": [
		`\bOpenSSL::Cipher(?:::Cipher)?\.new\s*\(\s*__ECB__`,
		`\bOpenSSL::Cipher::\w+\.new\s*\([^)]*(?::ECB\b|__ECB__)`,
	],
	"php": [
		`(?i)\bopenssl_(?:en|de)crypt\s*\([^;]*__ECB__`,
		`MODE_ECB\b`,
		`(?i)\bmcrypt_ecb\s*\(`,
		`(?i)\bmcrypt_(?:en|de)crypt\s*\([^;]*__ECB__`,
		`\bnew\s+\\?(?:[\w\\]*\\)?(?:AES|Rijndael|DES|TripleDES|Blowfish|Twofish|RC2)\s*\(\s*__ECB__`,
	],
}

# A call whose cipher argument comes on a following line.
_open_call := {
	"node": `\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*$`,
	"java": `\bCipher\.getInstance\s*\(\s*$`,
	"ruby": `\bOpenSSL::Cipher\.new\s*\(\s*$`,
	"php": `(?i)\bopenssl_(?:en|de)crypt\s*\([^)]*$`,
}

# Names bound to an ECB cipher name in this file.
_name_re := {
	"node": concat("", [`\b(?:const|let|var)\s+(\w+)\s*=\s*`, _ecb_lit]),
	"ruby": concat("", [`\b(\w+)\s*=\s*`, _ecb_lit]),
	"php": concat("", [`\$(\w+)\s*=\s*`, _ecb_lit]),
}

_names(lang, content) := ns if {
	re := _name_re[lang]
	ns := {m[1] | some m in regex.find_all_string_submatch_n(re, content, -1)}
}

_names("java", content) := _java_vars(content)

_names(lang, _) := set() if lang in {"python", "go"}

_use_re := {
	"node": [`\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*`, `\b`],
	"java": [`\bCipher\.getInstance\s*\(\s*`, `\s*[,)]`],
	"ruby": [`\bOpenSSL::Cipher\.new\s*\(\s*`, `\b`],
	"php": [`(?i)\bopenssl_(?:en|de)crypt\s*\([^;]*\$`, `\b`],
}

_bound(lang, names) := {concat("", [_use_re[lang][0], n, _use_re[lang][1]]) | some n in names}

_ecb_value := `(?i:[a-z0-9]+/ecb/[a-z0-9]+|[a-z0-9]+/ecb|aes|des|desede|tripledes|blowfish)`

_java_vars(content) := literal | defaults if {
	literal := {m[1] |
		some m in regex.find_all_string_submatch_n(concat("", [`\b(\w+)\s*=\s*"`, _ecb_value, `"\s*[;,)]`]), content, -1)
		not regex.match(`(?i)=\s*"(?:rsa|ecies|elgamal)/`, m[0])
	}
	defaults := {m[1] |
		some m in regex.find_all_string_submatch_n(concat("", [`\b(\w+)\s*=\s*[\w.]*getProperty\s*\(\s*"([^"]*)"\s*,\s*"`, _ecb_value, `"\s*\)\s*[;,)]`]), content, -1)
		not _overridden(m[2])
	}
}

# key=value pairs from the project's .properties files
_props := {[m[1], m[2]] |
	some p, c in input.file_contents
	endswith(p, ".properties")
	some m in regex.find_all_string_submatch_n(`(?m)^[ \t]*([\w.\-]+)[ \t]*[=:][ \t]*([^\s#]+)`, c, -1)
}

# A getProperty default is only the fallback: when the project's own
# properties set that key to a non-ECB transformation, the default never runs.
_overridden(key) if {
	some kv in _props
	kv[0] == key
	not regex.match(concat("", [`^`, _ecb_value, `$`]), kv[1])
}

_tokens("java", _) := {"ecb", "getinstance"}

_tokens("python", _) := {"ecb", "aes.new"}

_tokens("go", _) := {"ecb", "crypt("}

_tokens(lang, names) := {"ecb"} | {lower(n) | some n in names} if lang in {"node", "ruby", "php"}

_may(line, toks) if {
	l := lower(line)
	some t in toks
	contains(l, t)
}

_may(line, _) if endswith(trim_right(line, " \t\r"), "(")

_may(line, _) if endswith(trim_right(line, " \t\r"), ",")

_hit(_, _, _, code, pats, _) if {
	some p in pats
	regex.match(p, code)
}

_hit(lang, lines, i, code, _, _) if {
	regex.match(_open_call[lang], code)
	end := min([count(lines) - 1, i + 3])
	i + 1 <= end
	rest := concat(" ", [_code(lang, lines[k]) | some k in numbers.range(i + 1, end); not helpers.is_comment_line(lines[k])])
	regex.match(`^[^;]*?(?:__ECB__|^\s*__AESDEF__)`, rest)
}

# Go: a cipher.Block's Encrypt/Decrypt over successive slices in a loop.
_hit("go", lines, i, code, _, go_block) if {
	go_block
	regex.match(`\b\w+\.(?:En|De)crypt\s*\(\s*\w+\[[^\]]*:[^\]]*\]\s*,\s*\w+\[[^\]]*:[^\]]*\]`, code)
	some k in numbers.range(max([0, i - 4]), i - 1)
	regex.match(`^\s*for\b`, lines[k])
}

# A comparison against the ECB constant is a guard, not a use.
_excluded(code) if regex.match(`[=!]==?\s*[\w.:]*(?:MODE_ECB|mode\.ECB)\b`, code)

_excluded(code) if regex.match(`(?:MODE_ECB|mode\.ECB)\s*[=!]==?`, code)

_gate("java", content) if regex.match(`(?i)ecb|"(?:aes(?:_\d+)?|des|desede|tripledes|blowfish)"`, content)

_gate("python", content) if regex.match(`(?i)ecb|\bAES\.new\s*\(`, content)

_gate("go", content) if regex.match(`(?i)ecb`, content)

_gate("go", content) if {
	regex.match(`"crypto/(?:aes|des)"|"golang\.org/x/crypto/(?:blowfish|twofish|cast5|tea|xtea)"`, content)
	regex.match(`\.(?:En|De)crypt\(`, content)
}

_gate(lang, content) if {
	lang in {"node", "ruby", "php"}
	regex.match(`(?i)ecb`, content)
}

_go_block("go", content) if regex.match(`"crypto/(?:aes|des)"|"golang\.org/x/crypto/(?:blowfish|twofish|cast5|tea|xtea)"`, content)

_go_flag(lang, content) := true if _go_block(lang, content)

_go_flag(lang, content) := false if not _go_block(lang, content)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	not helpers.is_test_path(path)
	names := _names(lang, content)
	pats := {p | some p in _static[lang]} | _bound(lang, names)
	toks := _tokens(lang, names)
	go_block := _go_flag(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	_may(line, toks)
	count(line) < 1000 # a minified or bundled line is not the project's code
	not helpers.is_comment_line(line)
	code := _code(lang, line)
	_hit(lang, lines, i, code, pats, go_block)
	not _excluded(code)
	finding := {
		"rule_id": metadata.id,
		"message": "Block cipher used in ECB mode: equal plaintext blocks give equal ciphertext blocks and nothing detects tampering. Use AES-GCM (or ChaCha20-Poly1305) with a unique nonce",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

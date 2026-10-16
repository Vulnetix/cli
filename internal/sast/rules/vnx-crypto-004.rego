package vulnetix.rules.vnx_crypto_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-004",
	"name": "Broken or obsolete cipher",
	"description": "A broken or obsolete symmetric cipher is constructed: DES, Triple DES (3DES/DESede), RC4 (ARC4/ARCFOUR), RC2, Blowfish, CAST5 or IDEA. Reported: Python PyCryptodome DES/DES3/ARC4/ARC2/Blowfish/CAST.new() (from-import aliases resolved), cryptography algorithms.TripleDES/ARC4/Blowfish/CAST5/IDEA() and pyDes; Node.js crypto.createCipheriv/createDecipheriv/createCipher with a des/des-ede3/rc4/rc2/bf/cast name (literal or a constant assigned it) and CryptoJS.DES/TripleDES/RC4.encrypt/decrypt; Go crypto/des NewCipher/NewTripleDESCipher, crypto/rc4 NewCipher and golang.org/x/crypto blowfish/cast5 NewCipher (aliased import resolved); Java Cipher/KeyGenerator/SecretKeyFactory.getInstance with such a transformation or a PBEWith...AndDES/DESede/RC2/RC4 algorithm (literal, variable, constant or getProperty default), new SecretKeySpec(key, \"DES\"/\"RC4\"/...), DESKeySpec/DESedeKeySpec and BouncyCastle DES/DESede/RC4/RC2/Blowfish/CAST5/IDEA engines (VNX-928 reports the Kotlin forms; Java is reported here only, not by VNX-928 as well); Ruby OpenSSL::Cipher.new('des-ede3-cbc'/'rc4'/'bf-cbc'...) and OpenSSL::Cipher::DES/BF/RC4/RC2.new; PHP openssl_encrypt/openssl_decrypt with such a method (literal or variable), mcrypt MCRYPT_DES/3DES/BLOWFISH/RC2/ARCFOUR/CAST/IDEA and phpseclib DES/TripleDES/RC4/RC2/Blowfish. DES keys are brute-forced in hours, 64-bit-block ciphers (3DES, Blowfish, CAST5, IDEA, RC2) fall to Sweet32 birthday attacks, and RC4's keystream is biased; use AES-GCM or ChaCha20-Poly1305. Not reported: modern ciphers (AES, ChaCha20), TLS cipher-suite names in a deny-list, a cipher name in a list or comparison, constants such as des.BlockSize, the import alone, names that merely contain the letters (description, designer, rc4Count), names inside string literals or comments, documentation, and test files. Go is covered in more depth (cipher tables and TLS suites) by VNX-GO-010.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-004/",
	"languages": ["python", "node", "go", "java", "ruby", "php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["weak-crypto", "des", "rc4", "blowfish", "cipher"],
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

# A weak cipher-name literal ('des-ede3-cbc', "DESede/CBC/PKCS5Padding",
# 'rc4', "PBEWithMD5AndDES") becomes a sentinel before string literals are
# blanked, so the call that names it is recognisable while the same text in
# a longer string (a warning, prose) is not.
_weak := `(?:des|desede|des3|3des|tripledes|triple-des|rc4|arc4|arcfour|rc2|arc2|bf|blowfish|cast|cast5|cast-128|cast128|idea)(?:[-/_]\w+)*|pbewith\w*and(?:des|desede|tripledes|rc2|rc4)\w*`

_weak_lit := concat("", ["['\"`](?i:", _weak, ")['\"`]"])

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
	s := regex.replace(line, _weak_lit, "__WEAK__")
	t := regex.replace(s, _strings[lang], `""`)
	c := regex.replace(t, _tail_comment[lang], "")
}

_static := {
	"python": [
		`\bCrypto(?:dome)?\.Cipher\.(?:DES3?|ARC[24]|Blowfish|CAST)\.new\s*\(`,
		`\balgorithms\.(?:TripleDES|ARC4|Blowfish|CAST5|IDEA)\s*\(`,
		`\bpyDes\.(?:des|triple_des)\s*\(`,
	],
	"node": [
		`\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*__WEAK__`,
		`\bCryptoJS\.(?:DES|TripleDES|RC4|RC4Drop)\.(?:encrypt|decrypt)\s*\(`,
	],
	"go": [],
	"java": [
		`\b(?:Cipher|KeyGenerator|SecretKeyFactory)\.getInstance\s*\(\s*__WEAK__`,
		`\bnew\s+SecretKeySpec\s*\([^;]*,\s*__WEAK__\s*\)`,
		`\bnew\s+(?:DES|DESede)KeySpec\s*\(`,
		`\bnew\s+(?:DES|DESede|RC4|RC2|Blowfish|CAST5|IDEA|TripleDES)Engine\s*\(`,
	],
	"ruby": [
		`\bOpenSSL::Cipher(?:::Cipher)?\.new\s*\(\s*__WEAK__`,
		`\bOpenSSL::Cipher::(?:DES|BF|RC4|RC2|CAST5|IDEA)\.new\b`,
	],
	"php": [
		`(?i)\bopenssl_(?:en|de)crypt\s*\([^;]*__WEAK__`,
		`\bMCRYPT_(?:DES|3DES|TRIPLEDES|BLOWFISH|BLOWFISH_COMPAT|RC2|ARCFOUR|ARCFOUR_IV|CAST_128|CAST_256|IDEA)\b`,
		`(?i)\bmcrypt_(?:encrypt|decrypt|module_open)\s*\(\s*__WEAK__`,
		`\bnew\s+\\?(?:[\w\\]*\\)?(?:DES|TripleDES|RC4|RC2|Blowfish)\s*\(`,
	],
}

# A call whose cipher argument comes on a following line.
_open_call := {
	"node": `\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*$`,
	"java": `\b(?:Cipher|KeyGenerator|SecretKeyFactory)\.getInstance\s*\(\s*$`,
	"ruby": `\bOpenSSL::Cipher\.new\s*\(\s*$`,
	"php": `(?i)\bopenssl_(?:en|de)crypt\s*\([^)]*$`,
}

# ── names bound by imports or assignments ───────────────────────────────

_import_names(list, want) := {n |
	some part in split(regex.replace(list, `[()]`, ""), ",")
	m := regex.find_all_string_submatch_n(concat("", [`^\s*`, want, `(?:\s+as\s+(\w+))?\s*$`]), part, 1)
	count(m) > 0
	n := _alias_or(m[0][1], want)
}

_alias_or(alias, want) := want if alias == ""

_alias_or(alias, _) := alias if alias != ""

_bound("python", content) := a | b if {
	a := {concat("", [`(?:^|[^\w.])`, n, `\.new\s*\(`]) |
		some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+Crypto(?:dome)?\.Cipher\s+import\s+([^\n#]+)`, content, -1)
		some want in ["DES", "DES3", "ARC4", "ARC2", "Blowfish", "CAST"]
		some n in _import_names(m[1], want)
	}
	b := {concat("", [`(?:^|[^\w.])`, n, `\s*\(`]) |
		regex.match(`(?m)^\s*from\s+pyDes\s+import\b`, content)
		some n in ["des", "triple_des"]
	}
}

_var_names(lang, content) := {m[1] |
	re := _var_re[lang]
	some m in regex.find_all_string_submatch_n(re, content, -1)
}

_var_re := {
	"node": concat("", [`\b(?:const|let|var)\s+(\w+)\s*=\s*`, _weak_lit]),
	"ruby": concat("", [`\b(\w+)\s*=\s*`, _weak_lit]),
	"php": concat("", [`\$(\w+)\s*=\s*`, _weak_lit]),
	"java": concat("", [`\b(\w+)\s*=\s*(?:`, _weak_lit, `|[\w.]*getProperty\s*\(\s*"[^"]*"\s*,\s*`, _weak_lit, `\s*\))\s*[;,)]`]),
}

_use_re := {
	"node": [`\bcreate(?:Cipher|Decipher)(?:iv)?\s*\(\s*`, `\b`],
	"java": [`\b(?:Cipher|KeyGenerator|SecretKeyFactory)\.getInstance\s*\(\s*`, `\s*[,)]`],
	"ruby": [`\bOpenSSL::Cipher\.new\s*\(\s*`, `\b`],
	"php": [`(?i)\bopenssl_(?:en|de)crypt\s*\([^;]*\$`, `\b`],
}

_bound(lang, content) := {concat("", [_use_re[lang][0], n, _use_re[lang][1]]) | some n in _var_names(lang, content)} if lang in {"node", "java", "ruby", "php"}

# Go: package local names for the weak cipher packages.
_go_pkgs := {
	"crypto/des": {"pkg": "des", "funcs": `NewCipher|NewTripleDESCipher`},
	"crypto/rc4": {"pkg": "rc4", "funcs": `NewCipher`},
	"golang.org/x/crypto/blowfish": {"pkg": "blowfish", "funcs": `NewCipher|NewSaltedCipher`},
	"golang.org/x/crypto/cast5": {"pkg": "cast5", "funcs": `NewCipher`},
}

_bound("go", content) := {concat("", [`(?:^|[^\w.])`, n, `\.(?:`, p.funcs, `)\b`]) |
	some ip, p in _go_pkgs
	contains(content, concat("", ["\"", ip, "\""]))
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*(?:import\s+)?(?:(\w+)\s+)?"`, replace(ip, ".", `\.`), `"`]), content, -1)
	not m[1] in {"_", "."}
	n := _alias_or(m[1], p.pkg)
}

# File gate and line prefilter: some trace of a weak cipher.
_gate_re := {
	"python": `\b(?:DES3?|ARC[24]|Blowfish|CAST5?|TripleDES|IDEA|pyDes)\b`,
	"node": "(?i)['\"`](?:des|des3|3des|tripledes|rc4|arc4|arcfour|rc2|bf|blowfish|cast5?|idea)\\b|CryptoJS\\.(?:DES|TripleDES|RC4)",
	"go": `"(?:crypto/(?:des|rc4)|golang\.org/x/crypto/(?:blowfish|cast5))"`,
	"java": `(?i)"(?:des|desede|des3|tripledes|rc4|arc4|arcfour|rc2|blowfish|cast5|idea|pbewith\w*and(?:des|desede|tripledes|rc2|rc4))\b|DES(?:ede)?KeySpec|(?:DES|DESede|RC4|RC2|Blowfish|CAST5|IDEA|TripleDES)Engine`,
	"ruby": `(?i)['"](?:des|rc4|rc2|bf|blowfish|cast5?|idea)\b|OpenSSL::Cipher::(?:DES|BF|RC4|RC2|CAST5|IDEA)\b`,
	"php": `(?i)['"](?:des|tripledes|rc4|arcfour|rc2|bf|blowfish|cast5?|idea)\b|MCRYPT_(?:DES|3DES|TRIPLEDES|BLOWFISH|RC2|ARCFOUR|CAST|IDEA)|\b(?:DES|TripleDES|RC4|RC2|Blowfish)\s*\(`,
}

_line_re := {
	"python": `\b(?:DES3?|ARC[24]|Blowfish|CAST5?|TripleDES|IDEA|pyDes|des|triple_des)\b|\.new\s*\(`,
	"node": _gate_re.node,
	"go": `\.New\w*Cipher\b`,
	"java": _gate_re.java,
	"ruby": _gate_re.ruby,
	"php": _gate_re.php,
}

_may(_, line, _) if endswith(trim_right(line, " \t\r"), "(")

_may(lang, line, _) if regex.match(_line_re[lang], line)

_may(_, line, names) if {
	some n in names
	contains(line, n)
}

_hit(_, _, _, code, pats) if {
	some p in pats
	regex.match(p, code)
}

_hit(lang, lines, i, code, _) if {
	regex.match(_open_call[lang], code)
	end := min([count(lines) - 1, i + 3])
	i + 1 <= end
	rest := concat(" ", [_code(lang, lines[k]) | some k in numbers.range(i + 1, end); not helpers.is_comment_line(lines[k])])
	regex.match(`^[^;]*?__WEAK__`, rest)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate_re[lang], content)
	not helpers.is_test_path(path)
	names := _var_names(lang, content)
	pats := {p | some p in _static[lang]} | _bound(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	_may(lang, line, names)
	count(line) < 1000 # a minified or bundled line is not the project's code
	not helpers.is_comment_line(line)
	code := _code(lang, line)
	_hit(lang, lines, i, code, pats)
	finding := {
		"rule_id": metadata.id,
		"message": "Broken or obsolete cipher (DES, 3DES, RC4, RC2, Blowfish, CAST5 or IDEA) constructed here; use AES-GCM or ChaCha20-Poly1305",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

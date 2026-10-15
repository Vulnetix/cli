package vulnetix.rules.vnx_crypto_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-007",
	"name": "Weak password hashing (insufficient iterations or missing KDF)",
	"description": "A password is protected with a fast general-purpose hash, or with a password KDF whose work factor is far too low. Reported, when the hashed argument names a password (password, passwd, passphrase, pwd, $pass, pass_new, userPassword and similar): Python hashlib.md5/sha1/sha224/sha256/sha384/sha512/sha3_*/blake2 (also from-imported and hashlib.new('<alg>', ...)) and h.update(password) on such a hasher; Node.js crypto.createHash('<alg>').update(password) (chained across lines too), hasher.update(password) and CryptoJS.MD5/SHA1/SHA256/SHA512(password); Java MessageDigest md.update/digest(password...) (one line or on a digest obtained in the lines above), commons-codec DigestUtils.md5/sha1/sha256Hex(password) and Guava Hashing.sha256().hashString(password); PHP md5/sha1($pass) and hash('<alg>', ... $password); Ruby Digest::MD5/SHA1/SHA256.hexdigest(password) and OpenSSL::Digest::*.hexdigest; Go md5.Sum/sha1.Sum/sha256.Sum256/sha512.Sum512 and h.Write/io.WriteString on a hasher from md5/sha1/sha256/sha512.New() assigned just above; and in every language a call to a helper named for the hash (Md5Sum(r.FormValue(\"password\")), sha256Hex(pwd)). A form or parameter read by literal name (r.FormValue(\"password\"), getParameter(\"password\"), $_POST['password']) counts as a password-named value. Also reported, given literally or through a constant in the same file: PBKDF2 with fewer than 10,000 iterations (Python hashlib.pbkdf2_hmac, cryptography PBKDF2HMAC, PyCryptodome PBKDF2 count=; Node.js pbkdf2/pbkdf2Sync; Java PBEKeySpec/PBEParameterSpec; PHP hash_pbkdf2; Ruby PKCS5/KDF pbkdf2_hmac; Go pbkdf2.Key) and a bcrypt cost below 10 (Python gensalt(rounds=), Node.js bcrypt.hash/genSalt, Java BCryptPasswordEncoder/BCrypt.gensalt, PHP password_hash 'cost' =>, Ruby Password.create(cost:); Go bcrypt.GenerateFromPassword with a literal cost or bcrypt.MinCost). Use argon2id, scrypt, bcrypt (cost 10+) or PBKDF2 with hundreds of thousands of iterations. Not reported: bcrypt/scrypt/argon2 at normal cost, hashing data that is not a password (URLs, bodies, cache keys, reset or bypass tokens, passport numbers), helpers whose names say they verify, compare or already use a KDF (verify_sha256_password, pbkdf2_sha256.hash, sha256_crypt.hash), the SHA-1 prefix lookup against the Have I Been Pwned range API, a password hashed by a project helper defined elsewhere (a cross-function gap), the call inside a string or comment, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-007/",
	"languages": ["python", "node", "java", "php", "ruby", "go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [916],
	"capec": ["CAPEC-16"],
	"attack_technique": ["T1110.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "password-hashing", "weak-crypto"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if {
	regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)
	not endswith(path, ".min.js")
}

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "ruby" if endswith(path, ".rb")

_lang(path) := "go" if endswith(path, ".go")

_strings := {
	"python": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"node": "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`",
	"java": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"php": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"ruby": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"go": "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`",
}

_tail_comment := {
	"python": `#.*$`,
	"node": `//.*$`,
	"java": `//.*$`,
	"php": `(?://|#).*$`,
	"ruby": `#.*$`,
	"go": `//.*$`,
}

# A fast-hash name literal ('md5', "SHA-256") and PHP's 'cost' key become
# sentinels before string literals are blanked.
_code(lang, line) := c if {
	s1 := regex.replace(line, `['"](?i:md5|sha-?(?:1|224|256|384|512)|sha3-\d+|sha)['"]`, "__FAST__")
	s2 := regex.replace(s1, `['"]cost['"]`, "__COST__")
	# a subscript key ($_POST['password'], req.body["password"]) keeps its
	# name, so the argument still says what it is once strings are blanked
	s3 := regex.replace(s2, `\[\s*['"](\w+)['"]\s*\]`, "[__k_${1}]")
	# and so does a form or parameter read by a literal name
	# (r.FormValue("password"), request.getParameter("password"))
	s4 := regex.replace(s3, `\.(?:FormValue|PostFormValue|getParameter|get|param|fetch|input|post|query|Get)\s*\(\s*['"](\w+)['"]\s*\)`, ".__k_${1}")
	t := regex.replace(s4, _strings[lang], `""`)
	c := regex.replace(t, _tail_comment[lang], "")
}

# ── fast hash over a password ───────────────────────────────────────────
# Each pattern's last capture group is the text after the call opens.
_fast := {
	"python": [
		`\bhashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+|blake2[bs])\s*\((.*)$`,
		`\bhashlib\.new\s*\(\s*__FAST__\s*,(.*)$`,
	],
	"node": [
		`\bcreateHash\s*\(\s*__FAST__\s*\)\s*\.update\s*\((.*)$`,
		`\bCryptoJS\.(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3)\s*\((.*)$`,
	],
	"java": [
		`\bMessageDigest\.getInstance\s*\([^)]*\)\s*\.(?:digest|update)\s*\((.*)$`,
		`\bDigestUtils\.(?:md5|sha1|sha256|sha384|sha512|sha|md2)(?:Hex)?\s*\((.*)$`,
		`\bHashing\.(?:md5|sha1|sha256|sha384|sha512)\s*\(\s*\)\s*\.hash\w*\s*\((.*)$`,
	],
	"php": [
		`(?i)(?:^|[^\w>:$\\])(?:md5|sha1)\s*\((.*)$`,
		`(?i)\bhash\s*\(\s*__FAST__\s*,(.*)$`,
	],
	"go": [
		`\b(?:md5|sha1)\.Sum\s*\((.*)$`,
		`\bsha256\.Sum(?:256|224)\s*\((.*)$`,
		`\bsha512\.Sum(?:512|384|512_256)\s*\((.*)$`,
	],
	"ruby": [`\b(?:OpenSSL::)?Digest::(?:MD5|SHA1|SHA256|SHA384|SHA512|SHA2|RMD160)\.(?:hexdigest|digest|base64digest)\s*\(?(.*)$`],
}

# Python names from-imported from hashlib
_py_imported(content) := {n |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*from\s+hashlib\s+import\s+([^\n#]+)`, content, -1)
	some part in split(regex.replace(m[1], `[()]`, ""), ",")
	t := regex.split(`\s+as\s+`, trim_space(part))
	t[0] in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
	n := t[count(t) - 1]
}

# a hasher object assigned in the lines above: v = hashlib.sha256() / crypto.createHash('md5') / MessageDigest.getInstance(...)
_ctor := {
	"python": `\s*=\s*hashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+|blake2[bs]|new)\s*\(`,
	"node": `\s*=\s*(?:crypto\.)?createHash\s*\(\s*['"](?i:md5|sha-?(?:1|224|256|384|512)|sha3-\d+)['"]\s*\)\s*;?\s*$`,
	"java": `\s*=\s*MessageDigest\.getInstance\s*\(`,
}

# A helper named for the hash it computes: Md5Sum(r.FormValue("password")),
# sha256Hex(password), hashMD5(pwd). Verifiers and comparers are not hashing.
_pw_rest(_, _, _, code, _) if {
	some m in regex.find_all_string_submatch_n(`(?:^|[^\w$])(\w*(?i:md5|sha1|sha256|sha512)\w*)\s*\((.*)$`, code, -1)
	not regex.match(`(?i)verify|check|compare|equal|match|valid|hmac|crypt|pbkdf|bcrypt`, m[1])
	_names_password(m[2])
}

# Go: h := sha256.New() / md5.New() above, then h.Write([]byte(password)) or
# io.WriteString(h, password)
_pw_rest("go", lines, i, code, _) if {
	some m in regex.find_all_string_submatch_n(`\b(?:(\w+)\.Write(?:String)?\s*\((.*)$|io\.WriteString\s*\(\s*(\w+)\s*,(.*)$)`, code, -1)
	v := concat("", [m[1], m[3]])
	rest := concat("", [m[2], m[4]])
	re := concat("", [`\b`, v, `\s*:?=\s*(?:md5|sha1|sha256|sha512)\.New(?:224|384)?\s*\(`])
	some k in numbers.range(max([0, i - 8]), i - 1)
	k < i
	regex.match(re, lines[k])
	_names_password(rest)
}

_pw_rest(lang, _, _, code, _) if {
	some p in _fast[lang]
	m := regex.find_all_string_submatch_n(p, code, 1)
	count(m) > 0
	_names_password(m[0][count(m[0]) - 1])
}

_pw_rest("python", _, _, code, imported) if {
	some n in imported
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, n, `\s*\((.*)$`]), code, 1)
	count(m) > 0
	_names_password(m[0][1])
}

# Node: a .update( line continuing crypto.createHash('<alg>') from just above
_pw_rest("node", lines, i, code, _) if {
	m := regex.find_all_string_submatch_n(`^\s*\.update\s*\((.*)$`, code, 1)
	count(m) > 0
	some k in numbers.range(max([0, i - 2]), i - 1)
	k < i
	regex.match(`\bcreateHash\s*\(\s*['"](?i:md5|sha-?(?:1|224|256|384|512)|sha3-\d+)['"]\s*\)\s*$`, trim_space(lines[k]))
	_names_password(m[0][1])
}

# v.update(...)/v.digest(...) on a hasher assigned in the 8 lines above
_pw_rest(lang, lines, i, code, _) if {
	_ctor[lang]
	m := regex.find_all_string_submatch_n(`\b(\w+)\.(?:update|digest)\s*\((.*)$`, code, 1)
	count(m) > 0
	v := m[0][1]
	re := concat("", [`\b`, v, _ctor[lang]])
	some k in numbers.range(max([0, i - 8]), i - 1)
	k < i
	regex.match(re, lines[k])
	_names_password(m[0][2])
}

_ident_re := `[A-Za-z_$][\w$]*`

_pw_ident(id) if {
	regex.match(`(?i)passw(?:or)?d|passphrase`, id)
	not _not_pw(id)
}

_pw_ident(id) if {
	regex.match(`(?i)^\$?(?:pass|pwd|pw)(?:_[a-z]\w*)?$|_(?:pass|pwd)$|[a-z](?:Pass|Pwd)$`, id)
	not _not_pw(id)
}

_not_pw(id) if regex.match(`(?i)token|reset|hash|digest|length|len$|policy|field|label|url|hint|count|attempt|expir|strength|regex|rule|error|msg|message|salt|key|through|port`, id)

_names_password(rest) if {
	some id in regex.find_n(_ident_re, rest, -1)
	_pw_ident(id)
}

# SHA-1 prefix lookup against the Have I Been Pwned range API
_pwned_check(lines, i) if {
	w := helpers.code_window(lines, i, 4, 4)
	regex.match(`(?i)pwned|/range/|\[:5\]|substr\s*\([^)]*,\s*0\s*,\s*5\s*\)`, w)
}

_fast_hit(lang, lines, i, code, imported) if {
	_pw_rest(lang, lines, i, code, imported)
	not regex.match(`(?i)hmac`, code)
	not _pwned_check(lines, i)
}

# ── PBKDF2 iterations and bcrypt cost ──────────────────────────────────
_iter_pats := {
	"python": [
		`\bpbkdf2_hmac\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*(?:iterations\s*=\s*)?(\w+)`,
		`\bPBKDF2HMAC\s*\(.*\biterations\s*=\s*(\w+)`,
		`\bPBKDF2\s*\(.*\bcount\s*=\s*(\w+)`,
	],
	"node": [`\bpbkdf2(?:Sync)?\s*\(\s*[^,]+,\s*[^,]+,\s*(\w+)\s*,`],
	"java": [
		`\bnew\s+PBEKeySpec\s*\(\s*[^,]+,\s*[^,]+,\s*(\w+)`,
		`\bnew\s+PBEParameterSpec\s*\(\s*[^,]+,\s*(\w+)`,
	],
	"php": [`\bhash_pbkdf2\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*(\w+)`],
	"go": [`\bpbkdf2\.Key\s*\(\s*[^,]+,\s*[^,]+,\s*(\w+)\s*,`],
	"ruby": [
		`\bpbkdf2_hmac(?:_sha1)?\s*\(\s*[^,:]+,\s*[^,:]+,\s*(\w+)\s*,`,
		`\bpbkdf2_hmac\s*\(.*\biterations:\s*(\w+)`,
	],
}

_cost_pats := {
	"python": [`\bgensalt\s*\(\s*(?:rounds\s*=\s*)?(\w+)\s*[,)]`],
	"node": [
		`\bbcrypt\w*\.(?:hash|hashSync)\s*\([^,]+,\s*(\w+)\s*[,)]`,
		`\bbcrypt\w*\.genSalt(?:Sync)?\s*\(\s*(\w+)\s*[,)]`,
	],
	"java": [
		`\bnew\s+BCryptPasswordEncoder\s*\(\s*(\w+)\s*[,)]`,
		`\bBCrypt\.gensalt\s*\(\s*(\w+)\s*[,)]`,
	],
	"php": [`\bpassword_hash\s*\(.*__COST__\s*=>\s*(\w+)`],
	"ruby": [`\bPassword\.create\s*\(.*\bcost:\s*(\w+)`],
	"go": [`\bbcrypt\.GenerateFromPassword\s*\(\s*[^,]+,\s*(?:bcrypt\.)?(\w+)\s*\)`],
}

_consts(content) := {[m[1], to_number(replace(m[2], "_", ""))] |
	some m in regex.find_all_string_submatch_n(`(?m)\b([A-Za-z_]\w*)\s*:?=\s*(\d[\d_]*)\s*;?\s*(?:(?://|#).*)?$`, content, -1)
}

_values(tok, _) := {to_number(replace(tok, "_", ""))} if regex.match(`^\d[\d_]*$`, tok)

_values(tok, content) := {c[1] | some c in _consts(content); c[0] == tok} if {
	not regex.match(`^\d`, tok)
	tok != "MinCost"
}

# golang.org/x/crypto/bcrypt.MinCost is 4
_values("MinCost", _) := {4}

_low_iter(tok, consts) if {
	some n in _values(tok, consts)
	n < 10000
}

_low_cost(tok, consts) if {
	some n in _values(tok, consts)
	n < 10
}

_param_hit(lang, _, _, code, consts) if {
	some p in _iter_pats[lang]
	m := regex.find_all_string_submatch_n(p, code, 1)
	count(m) > 0
	_low_iter(m[0][1], consts)
}

_param_hit(lang, _, _, code, consts) if {
	some p in _cost_pats[lang]
	m := regex.find_all_string_submatch_n(p, code, 1)
	count(m) > 0
	_low_cost(m[0][1], consts)
}

# cryptography PBKDF2HMAC( wrapped, iterations=N on its own line
_param_hit("python", lines, i, code, consts) if {
	m := regex.find_all_string_submatch_n(`^\s*iterations\s*=\s*(\w+)\s*,?\s*\)?\s*$`, code, 1)
	count(m) > 0
	some k in numbers.range(max([0, i - 6]), i - 1)
	k < i
	regex.match(`\bPBKDF2HMAC\s*\(`, lines[k])
	_low_iter(m[0][1], consts)
}

_pw_tokens := ["pass", "Pass", "PASS", "pwd", "Pwd", "PWD", "pw", "pbkdf2", "PBKDF2", "bcrypt", "BCrypt", "gensalt", "PBE"]

_api_tokens := ["hashlib", "createHash", "CryptoJS.", "MessageDigest", "DigestUtils", "Hashing.", "Digest::", "md5(", "md5 (", "MD5(", "sha1(", "sha1 (", "SHA1(", "hash(", "hash (", "pbkdf2", "PBKDF2", "PBEKeySpec", "PBEParameterSpec", "bcrypt", "BCrypt", "gensalt", "Password.create", "Md5", "Sha1", "Sha256", "SHA256", "Sha512", "Sum256", "Sum512", "md5.Sum", "sha1.Sum", ".New()", "GenerateFromPassword"]

_has_any(content, toks) if {
	some t in toks
	contains(content, t)
}

_line_gate := `pass|Pass|PASS|pwd|Pwd|PWD|pw\b|PW\b|pbkdf2|PBKDF2|bcrypt|BCrypt|gensalt|PBE|cost|iterations|count`

_line_api := `md5|MD5|Md5|Sum|Write|GenerateFromPassword|sha|SHA|Sha|igest|update|pbkdf2|PBKDF2|bcrypt|BCrypt|gensalt|PBE|cost|iterations|count|blake|hash\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _api_tokens)
	_has_any(content, _pw_tokens)
	not helpers.is_test_path(path)
	imported := _imported(lang, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 1000
	regex.match(_line_gate, line)
	regex.match(_line_api, line)
	not helpers.is_comment_line(line)
	code := _code(lang, line)
	_any_hit(lang, lines, i, code, imported, content)
	finding := {
		"rule_id": metadata.id,
		"message": "Password protected by a fast hash or a KDF with too low a work factor; use argon2id, scrypt, bcrypt (cost 10 or more) or PBKDF2 with hundreds of thousands of iterations",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_imported("python", content) := _py_imported(content)

_imported(lang, _) := set() if lang != "python"

_any_hit(lang, lines, i, code, imported, _) if _fast_hit(lang, lines, i, code, imported)

_any_hit(lang, lines, i, code, _, content) if _param_hit(lang, lines, i, code, content)

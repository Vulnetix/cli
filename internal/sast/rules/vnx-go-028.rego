package vulnetix.rules.vnx_go_028

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-028",
	"name": "Use of weak cryptographic hash for password hashing",
	"description": "A password is hashed with a fast general-purpose digest: md5.Sum, sha1.Sum, sha256.Sum256/Sum224 or sha512.Sum512/Sum384 called on it, a hasher from md5.New/sha1.New/sha256.New/sha512.New (or crypto.MD5.New...) written with it (h.Write, io.WriteString), or a helper whose name says MD5/SHA (Md5Sum, util.SHA1Hex) called with it. MD5 and SHA-1 are broken, and none of these has a salt or a work factor, so a leaked hash table falls to GPU guessing; use bcrypt, scrypt, Argon2id or PBKDF2. The argument must name a password (password/passwd/pwd/pass/passphrase, or a request field \"password\"). Not reported: bcrypt, argon2, scrypt, pbkdf2 and HMAC (a hash passed as a function value), digests of other data (file contents, API keys and reset tokens, which are random, and names such as passwordResetToken or passwordPolicy), protocol-mandated digests (HTTP Digest realm/nonce responses, MySQL scramble, CRAM/NTLM/CHAP challenge functions), test files, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-028/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327, 916],
	"capec": ["CAPEC-32"],
	"attack_technique": ["T1068.003"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["cryptography", "password", "hash", "weak-crypto"],
}

# A word that names a password.
_pw_re := `(?i)passw(?:or)?d|passwd|\bpwd|pwd\b|passphrase|passcode|\bpass\b|\bpw\b`

# ...but not a value derived from or about one.
_not_pw_re := `(?i)token|reset|polic|hint|len|field|label|prompt|url|env|file|path|regex|pattern|rule|expir|age|histor|changed|flag|enabled|count|attempt|required|strength|confirm|placeholder|name|key`

_names_password(args) if {
	some w in regex.find_all_string_submatch_n(`[A-Za-z_]\w*`, args, -1)
	regex.match(_pw_re, w[0])
	not regex.match(_not_pw_re, w[0])
}

_algo(s) := "MD5" if regex.match(`(?i)md5`, s)

_algo(s) := "SHA-1" if {
	not regex.match(`(?i)md5`, s)
	regex.match(`(?i)sha_?1(?:[^\d]|$)`, s)
}

_algo(s) := "SHA-2" if {
	not regex.match(`(?i)md5|sha_?1(?:[^\d]|$)`, s)
	regex.match(`(?i)sha_?(?:256|224|384|512)`, s)
}

# One-shot digests: md5.Sum(x), sha256.Sum256(x).
_direct_re := `\b(?:md5|sha1|sha256|sha512)\.Sum(?:224|256|384|512|512_224|512_256)?\(`

# A helper named for the digest: Md5Sum(x), util.SHA1Hex(x), hashSHA256(x).
_helper_re := `\b\w*(?i:md5|sha_?1|sha_?256|sha_?512)\w*\(`

# A hasher variable.
_hasher_re := `^\s*(\w+)\s*:?=\s*(?:(?:md5|sha1|sha256|sha512)\.New(?:224|384|512_224|512_256)?\(\)|crypto\.(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\.New\(\))`

# Code text: string literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

# The call's arguments, with continuation lines of a call broken after '('.
_args(_, _, line, rest) := rest if not regex.match(`[(,]\s*$`, line)

_args(lines, i, line, rest) := a if {
	regex.match(`[(,]\s*$`, line)
	end := min([count(lines) - 1, i + 3])
	a := concat(" ", array.concat([rest], [lines[k] | some k in numbers.range(i + 1, end)]))
}

_after(line, m) := substring(line, indexof(line, m) + count(m), -1)

# Direct digest of a password.
_hashes(lines, i, line, code) := algo if {
	ms := regex.find_all_string_submatch_n(_direct_re, code, 1)
	count(ms) > 0
	args := _args(lines, i, line, _after(line, ms[0][0]))
	_names_password(args)
	algo := _algo(ms[0][0])
}

# A call to a helper named for the digest (not its own declaration).
_hashes(lines, i, line, code) := algo if {
	not startswith(line, "func ")
	not regex.match(_direct_re, code)
	ms := regex.find_all_string_submatch_n(_helper_re, code, 1)
	count(ms) > 0
	not regex.match(`\.New\w*\($`, ms[0][0])
	args := _args(lines, i, line, _after(line, ms[0][0]))
	_names_password(args)
	algo := _algo(ms[0][0])
}

# h.Write(pw) / io.WriteString(h, pw) on a hasher created above in the function.
_hashes(lines, i, line, code) := algo if {
	ws := regex.find_all_string_submatch_n(`\bio\.WriteString\(\s*(\w+)\s*,|\b(\w+)\.Write(?:String)?\(|\bfmt\.Fprint\w*\(\s*(\w+)\s*,`, code, 1)
	count(ws) > 0
	h := concat("", [ws[0][1], ws[0][2], ws[0][3]])
	_names_password(_after(line, ws[0][0]))
	some k in numbers.range(_fn_start(lines, i), i - 1)
	hm := regex.find_all_string_submatch_n(_hasher_re, lines[k], 1)
	count(hm) > 0
	hm[0][1] == h
	algo := _algo(lines[k])
}

_fn_start(lines, i) := max(array.concat([max([0, i - 30])], [j | some j in numbers.range(max([0, i - 30]), i); startswith(lines[j], "func ")]))

# The digest a wire protocol mandates: HTTP Digest, MySQL scramble, CRAM,
# NTLM, CHAP and other challenge-response computations.
_protocol_re := `(?i)realm|nonce|scramble|challenge|cram_?md5|ntlm|\bchap\b|\bha1\b|handshake|digest_?(?:auth|response|header|challenge)`

_protocol(lines, i, line) if regex.match(`(?i)realm|nonce|scramble|challenge|\bha1\b`, line)

_protocol(lines, i, _) if {
	fs := _fn_start(lines, i)
	startswith(lines[fs], "func ")
	regex.match(_protocol_re, lines[fs])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?i)md5|sha1|sha256|sha512|sha_1`, content)
	regex.match(_pw_re, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "(")
	_candidate(line)
	not helpers.is_comment_line(line)
	code := _code(line)
	some algo in {a | a := _hashes(lines, i, line, code)}
	not _protocol(lines, i, line)
	not _in_kdf(path, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Password hashed with %s, a fast unsalted digest: a leaked hash falls to GPU guessing. Use bcrypt, scrypt, Argon2id or PBKDF2 (golang.org/x/crypto)", [algo]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The line names a password, or opens a call whose arguments continue below.
_candidate(line) if regex.match(_pw_re, line)

_candidate(line) if regex.match(`[(,]\s*$`, line)

# The digest is a step of a real KDF: a pre-hash handed to bcrypt/scrypt/
# argon2/pbkdf2 a few lines on, or the body of a KDF implementation (a
# function taking rounds or iterations, a file named for the KDF).
_kdf_re := `\b(?:bcrypt|scrypt|argon2|pbkdf2|hkdf)\.`

_in_kdf(path, _, _) if regex.match(`(?i)kdf|bcrypt|scrypt|argon2`, path)

_in_kdf(_, lines, i) if {
	fs := _fn_start(lines, i)
	startswith(lines[fs], "func ")
	regex.match(`(?i)kdf|bcrypt|scrypt|argon|\brounds\b|\biter(?:ation)?s?\b|\bcost\b`, lines[fs])
}

_in_kdf(_, lines, i) if {
	some k in numbers.range(_fn_start(lines, i), min([count(lines) - 1, i + 8]))
	regex.match(_kdf_re, lines[k])
}

# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_323

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-323",
	"name": "Reusing a Nonce, Key Pair in Encryption",
	"description": "An IV or nonce is generated once and then reused for every message encrypted under the same key: it is created at module, package or class level (or once in a constructor) and the encryption call inside a function or method uses it without generating a fresh one. With GCM, CTR and ChaCha20-Poly1305 a repeated nonce leaks the XOR of plaintexts and lets an attacker forge messages; with CBC it leaks equal prefixes. Reported: Python AESGCM/ChaCha20Poly1305/AESCCM .encrypt(nonce, ...), pycryptodome AES/ChaCha20 .new(..., nonce=/iv=), cryptography modes.CBC/CTR/GCM/CFB/OFB; Node crypto.createCipheriv(alg, key, iv) and WebCrypto { name: 'AES-GCM', iv }; Go AEAD .Seal(dst, nonce, ...) and cipher.NewCBCEncrypter/NewCTR/NewOFB/NewCFBEncrypter; Java new IvParameterSpec/GCMParameterSpec/ChaCha20ParameterSpec in an ENCRYPT_MODE init, whose IV argument is a module-level variable assigned from os.urandom/get_random_bytes/secrets.token_bytes/crypto.randomBytes/getRandomValues, a self./this. attribute set in __init__/constructor, a Go package-level variable or a struct field declared as []byte, or a Java byte[] field. Not reported: an IV or nonce assigned, filled (rand.Read, io.ReadFull, nextBytes, randomFillSync, getRandomValues) or incremented inside the encrypting function, decryption calls, and test files. Hard-coded constant IVs are VNX-CRYPTO-010's concern; flows through helpers and across files are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-323/",
	"languages": ["go", "java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [323],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["nonce-reuse", "cwe-323"],
}

_ivish(n) if regex.match(`(?i)(nonce|init_?vector|initiali[sz]ation_?vector)`, n)

_ivish(n) if regex.match(`((^|_)(iv|IV)(_|$)|^iv[A-Z0-9]|[a-z0-9]Iv$|[a-z0-9]IV$)`, n)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_bare(arg) := a if {
	a := trim_prefix(trim_prefix(arg, "self."), "this.")
}

# ── Sinks: (language, regex capturing the IV/nonce argument) ─────────────
_sinks := {
	"py": [
		`\.encrypt\(\s*((?:self\.)?[A-Za-z_]\w*)\s*,`,
		`\.new\([^)]*\b(?:nonce|iv)\s*=\s*((?:self\.)?[A-Za-z_]\w*)`,
		`\.new\(\s*[^,]+,\s*[\w.]*MODE_\w+\s*,\s*((?:self\.)?[A-Za-z_]\w*)\s*[,)]`,
		`\bmodes\.(?:CBC|CTR|GCM|CFB|CFB8|OFB)\(\s*((?:self\.)?[A-Za-z_]\w*)`,
	],
	"js": [
		`\bcreateCipheriv\([^,]+,[^,]+,\s*((?:this\.)?[A-Za-z_$][\w$]*)\s*[,)]`,
		`AES-(?:GCM|CBC|CTR)['"][^}]*\biv\s*:\s*((?:this\.)?[A-Za-z_$][\w$]*)`,
		`AES-(?:GCM|CBC|CTR)['"]\s*,\s*(iv|nonce)\s*[,}]`,
	],
	"go": [
		`\.Seal\(\s*[^,]+,\s*([A-Za-z_][\w.]*)\s*,`,
		`\bcipher\.New(?:CBCEncrypter|CTR|OFB|CFBEncrypter)\(\s*[^,]+,\s*([A-Za-z_][\w.]*)\s*\)`,
	],
	"java": [
		`\bnew\s+IvParameterSpec\(\s*((?:this\.)?[A-Za-z_]\w*)\s*\)`,
		`\bnew\s+GCMParameterSpec\(\s*[^,]+,\s*((?:this\.)?[A-Za-z_]\w*)\s*[,)]`,
		`\bnew\s+ChaCha20ParameterSpec\(\s*((?:this\.)?[A-Za-z_]\w*)\s*,`,
	],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if regex.match(`\.(js|ts|mjs|cjs|jsx|tsx)$`, path)

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "java" if endswith(path, ".java")

_gate := {
	"py": `(\.encrypt\(|\.new\(|modes\.)`,
	"js": `(createCipheriv|AES-)`,
	"go": `(\.Seal\(|cipher\.New)`,
	"java": `ParameterSpec\(`,
}

_rand_py := `(os\.urandom|secrets\.token_bytes|get_random_bytes|Random\.new\(\)\.read|random\.randbytes|token_bytes)\(`

_rand_js := `(randomBytes|getRandomValues|randomUUID)\(`

# ── Where the IV was created once ─────────────────────────────────────────

# Python module level: NONCE = os.urandom(12)
_once(lines, "py", arg, i) if {
	not startswith(arg, "self.")
	re := concat("", [`^`, arg, `\s*(?::\s*\w+\s*)?=\s*.*`, _rand_py])
	some l in lines
	regex.match(re, l)
}

# Python: self.nonce = os.urandom(12) inside __init__
_once(lines, "py", arg, i) if {
	startswith(arg, "self.")
	re := concat("", [`^\s+`, regex.replace(arg, `\.`, `\.`), `\s*=\s*.*`, _rand_py])
	some j, l in lines
	regex.match(re, l)
	_in_ctor(lines, j, `^\s*def\s+__init__\s*\(`)
}

# JavaScript module level: const iv = crypto.randomBytes(16)
_once(lines, "js", arg, i) if {
	not startswith(arg, "this.")
	re := concat("", [`^(?:export\s+)?(?:const|let|var)\s+`, arg, `\b[^=]*=\s*.*`, _rand_js])
	some l in lines
	regex.match(re, l)
}

# JavaScript: this.iv = crypto.randomBytes(16) inside constructor
_once(lines, "js", arg, i) if {
	startswith(arg, "this.")
	re := concat("", [`^\s+`, regex.replace(arg, `\.`, `\.`), `\s*=\s*.*`, _rand_js])
	some j, l in lines
	regex.match(re, l)
	_in_ctor(lines, j, `^\s*constructor\s*\(`)
}

# JavaScript/TypeScript class property initialiser: private readonly iv = randomBytes(12);
_once(lines, "js", arg, i) if {
	startswith(arg, "this.")
	re := concat("", [`^\s+(?:(?:private|public|protected|readonly|static)\s+)*`, _bare(arg), `\s*(?::\s*[\w<>\[\]]+\s*)?=\s*.*`, _rand_js])
	some l in lines
	regex.match(re, l)
}

# Go package-level variable: var nonce = ... / var nonce []byte
_once(lines, "go", arg, i) if {
	not contains(arg, ".")
	re := concat("", [`^var\s+`, arg, `\b`])
	some l in lines
	regex.match(re, l)
}

# Go struct field declared as []byte: c.nonce
_once(lines, "go", arg, i) if {
	parts := split(arg, ".")
	count(parts) == 2
	re := concat("", [`^\s+`, parts[1], `\s+\[\]byte\b`])
	some l in lines
	regex.match(re, l)
}

# Java byte[] field.
_once(lines, "java", arg, i) if {
	re := concat("", [`^\s*(?:@\w+\s+)*(?:(?:private|protected|public|static|final)\s+)+byte\s*\[\]\s*`, _bare(arg), `\s*[=;]`])
	some l in lines
	regex.match(re, l)
}

# Line j is inside the constructor whose header matches hdr.
_in_ctor(lines, j, hdr) if {
	some k in numbers.range(max([0, j - 25]), j - 1)
	regex.match(hdr, lines[k])
	_indent(lines[k]) < _indent(lines[j])
	not _header_between(lines, k, j)
}

_header_re := `^\s*(?:(?:async|static|public|private|protected|final|synchronized|override)\s+)*(?:def\s+\w+|func\s|function\b|constructor\s*\(|[\w<>\[\],]+\s+\w+\s*\([^;]*$|\w+\s*\([^)]*\)\s*(?::\s*[\w<>\[\]|, .]+)?\s*\{)`

_header_between(lines, k, j) if {
	k + 1 <= j - 1
	some m in helpers.span(k + 1, j - 1)
	regex.match(_header_re, lines[m])
	_indent(lines[m]) <= _indent(lines[k])
}

# The enclosing function's header line.
_fn_start(lines, i) := s if {
	ind := _indent(lines[i])
	hs := [k |
		some k in numbers.range(max([0, i - 60]), i - 1)
		regex.match(_header_re, lines[k])
		not regex.match(`^\s*(if|for|while|switch|catch|return|elif|else)\b`, lines[k])
		_indent(lines[k]) < ind
	]
	count(hs) > 0
	s := max(hs)
}

# The function fills or reassigns the IV before the call.
_refreshed(lines, s, i, arg) if {
	b := regex.replace(_bare(arg), `\.`, `\.`)
	re := concat("", [`(^\s*(?:(?:const|let|var|final|[\w<>\[\]]+)\s+)?(?:\w+\.)?`, b, `(?:\s*,\s*\w+)*\s*(?::=|=)[^=]|\b`, b, `\s*(\+\+|\+=)|(nextBytes|randomFillSync|getRandomValues|rand\.Read|ReadFull|increment\w*|fill\w*)\([^)]*\b`, b, `\b)`])
	some k in numbers.range(s, i)
	not helpers.is_comment_line(lines[k])
	regex.match(re, lines[k])
}

_java_encrypting(lines, i) if {
	some k in numbers.range(max([0, i - 8]), min([count(lines) - 1, i + 8]))
	contains(lines[k], "ENCRYPT_MODE")
}

_sink_ok(lines, "java", i) if _java_encrypting(lines, i)

_sink_ok(lines, lang, i) if lang != "java"

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	not helpers.is_test_path(path)
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	_indent(line) > 0
	not helpers.is_comment_line(line)
	some re in _sinks[lang]
	some m in regex.find_all_string_submatch_n(re, line, 2)
	arg := m[1]
	_ivish(_last(arg))
	_sink_ok(lines, lang, i)
	_once(lines, lang, arg, i)
	s := _fn_start(lines, i)
	not regex.match(`^\s*(def\s+__init__|constructor\s*\()`, lines[s])
	not _refreshed(lines, s + 1, i, arg)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IV/nonce %s is created once and reused for every encryption: generate a fresh random nonce per message", [arg]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_last(arg) := p if {
	parts := split(arg, ".")
	p := parts[count(parts) - 1]
}

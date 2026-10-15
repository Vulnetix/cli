# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_649

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-649",
	"name": "Client-held state decoded or decrypted and trusted without an integrity check",
	"description": "State the server handed to the client (a session, profile, coupon or token in a cookie, header, query or body field) comes back only base64/hex-encoded or encrypted in a malleable mode, and the server parses and trusts it without checking a MAC or signature, so the client can forge or flip it (CWE-649). Reported in Python and JavaScript/TypeScript: (1) a request value (request.cookies/COOKIES/args/form/headers/GET/POST/json, Tornado get_cookie(); req.cookies/query/body/headers/params, ctx.query/request) decoded with base64.b64decode/urlsafe_b64decode/decodebytes/a2b_base64, Buffer.from(x, 'base64'|'base64url'|'hex') or atob() and fed to json.loads/pickle.loads/yaml.load/ast.literal_eval/JSON.parse/qs.parse or split into fields, on one line (a parse call broken after its opening parenthesis is read with its next two lines) or through a variable up to six lines apart; (2) AES decryption in CBC/ECB/CTR/OFB/CFB mode (PyCryptodome cipher.decrypt, Node crypto.createDecipheriv('aes-...-cbc')) of such a value. Only files with no integrity check are reported: hmac/compare_digest/itsdangerous/Django signing/Fernet/JWT verify, createHmac/timingSafeEqual/cookie-signature/signedCookies/jsonwebtoken or jose verification (jwtVerify, compactVerify), or an authenticated mode (GCM, EAX, CCM, SIV, ChaCha20-Poly1305, NaCl). Not reported: HTTP Basic credentials decoded from the Authorization header, decoded binary payloads that are stored rather than parsed (uploads), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-649/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [649],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["relying-integrity", "integrity-check", "cookie", "cwe-649"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_src := {
	"py": `\brequest\.(?:cookies|COOKIES|args|form|values|headers|GET|POST|META|json|data|get_json\(|query_params)\b|\bself\.get_cookie\(`,
	"js": `\breq(?:uest)?\.(?:cookies|query|body|headers|params|get\(|header\()|\bctx\.(?:cookies\.get\(|query|request\.(?:body|query|headers))`,
}

_decode := {
	"py": `\b(?:b64decode|urlsafe_b64decode|standard_b64decode|decodebytes|a2b_base64|unhexlify)\(|\bbytes\.fromhex\(`,
	"js": `\bBuffer\.from\([^;]*['"](?:base64|base64url|hex)['"]|\batob\(`,
}

_parse_fn := {
	"py": `(?:json\.loads|pickle\.loads|yaml\.(?:safe_|unsafe_)?load|ast\.literal_eval|marshal\.loads)\(`,
	"js": `(?:JSON\.parse|qs\.parse|querystring\.parse)\(`,
}

_integrity := {
	"py": `hmac\.|compare_digest|itsdangerous|Signer|Serializer|signing\.|Fernet|jwt\.decode|\.verify\(|MODE_(?:GCM|EAX|CCM|SIV|OCB)|AESGCM|AESCCM|ChaCha20Poly1305|nacl\.|decrypt_and_verify`,
	"js": `createHmac|timingSafeEqual|jwt\.verify|\.verify\(|jwtVerify\(|compactVerify\(|flattenedVerify\(|jwtDecrypt\(|cookie-signature|unsign\(|signedCookies|setAuthTag|-gcm['"]|-ccm['"]|chacha20-poly1305|tweetnacl|sodium|subtle\.decrypt`,
}

_gate("py", c) if regex.match(`b64decode|decodebytes|a2b_base64|unhexlify|fromhex|\.decrypt\(`, c)

_gate("js", c) if regex.match(`base64|['"]hex['"]|atob\(|createDecipheriv`, c)

# String literals with whitespace are prose, not code.
_strip_prose(line) := c if {
	lits := [l |
		some l in regex.find_all_string_submatch_n(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\x60[^\x60]*\x60`, line, -1)
		regex.match(`\s`, l[0])
	]
	c := strings.replace_n({l[0]: `""` | some l in lits}, line)
}

# A value read from the Authorization header is a credential (HTTP Basic).
_auth_header(s) if regex.match(`(?i)authorization`, s)

# Variables assigned from a request value up to eight lines above i.
_tainted(lines, i, lang) := {v |
	some j in numbers.range(max([0, i - 8]), i - 1)
	prev := lines[j]
	regex.match(_src[lang], prev)
	not _auth_header(prev)
	not helpers.is_comment_line(prev)
	v := helpers.assigned_first(prev)
}

_refs(s, names) if {
	some n in names
	regex.match(concat("", [`(?:^|[^\w.$])`, n, `\b`]), s)
}

_untrusted(_, _, s, lang) if {
	regex.match(_src[lang], s)
	not _auth_header(s)
}

_untrusted(lines, i, s, lang) if _refs(s, _tainted(lines, i, lang))

# Variables assigned from a decode of an untrusted value up to six lines above.
_decoded(lines, i, lang) := {v |
	some j in numbers.range(max([0, i - 6]), i - 1)
	prev := _strip_prose(lines[j])
	regex.match(_decode[lang], prev)
	not helpers.is_comment_line(lines[j])
	_untrusted(lines, j, prev, lang)
	v := helpers.assigned_first(prev)
}

# Shape 1a: parse(decode(untrusted)) or decode(untrusted)...split() on one line.
_shape(lines, i, c, lang) if {
	regex.match(concat("", [_parse_fn[lang], `.*(?:`, _decode[lang], `)`]), c)
	_untrusted(lines, i, c, lang)
}

_shape(lines, i, c, lang) if {
	regex.match(concat("", [`(?:`, _decode[lang], `).*\)\s*(?:\.\w+\([^()]*\)\s*)*\.split\(`]), c)
	_untrusted(lines, i, c, lang)
}

# Shape 1b: parse(v) where v was decoded from an untrusted value just above.
_shape(lines, i, c, lang) if {
	regex.match(_parse_fn[lang], c)
	some v in _decoded(lines, i, lang)
	regex.match(concat("", [_parse_fn[lang], `\s*`, v, `\b`]), c)
}

# Shape 2: malleable-mode decryption of an untrusted value.
_shape(lines, i, c, "py") if {
	regex.match(`\.decrypt\(`, c)
	regex.match(`MODE_(?:CBC|ECB|CTR|OFB|CFB)|modes\.(?:CBC|ECB|CTR|OFB|CFB)\(`, concat("\n", lines))
	_untrusted(lines, i, c, "py")
}

_shape(lines, i, c, "js") if {
	regex.match(`createDecipheriv\(\s*['"](?:aes|des|des-ede3|camellia)-?(?:\d+-)?(?:cbc|ecb|ctr|ofb|cfb)`, c)
	w := helpers.code_window(lines, i, 0, 3)
	_untrusted(lines, i, w, "js")
}

# The call text: the line, or, when a parse call breaks right after its
# opening parenthesis, the line joined with the next two.
_call_text(_, _, line) := line if not regex.match(`\(\s*$`, line)

_call_text(lines, i, line) := concat(" ", array.concat([line], [trim_space(l) | some l in array.slice(lines, i + 1, i + 3)])) if regex.match(`\(\s*$`, line)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	regex.match(_src[lang], content)
	not regex.match(_integrity[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)parse|loads|load\(|literal_eval|split\(|decrypt|decipher`, line)
	not helpers.is_comment_line(line)
	c := _strip_prose(_call_text(lines, i, line))
	_shape(lines, i, c, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "Client-held state is only encoded or encrypted, not authenticated: it is decoded and trusted without a MAC or signature check, so the client can forge or alter it. Sign it (HMAC, itsdangerous, cookie-signature), use authenticated encryption (AES-GCM, Fernet), or keep it server-side",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

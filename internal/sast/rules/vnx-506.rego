# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_506

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-506",
	"name": "Embedded Malicious Code: execution of decoded payload",
	"description": "Code that decodes an encoded blob and executes the result, the loader shape of embedded malicious code (droppers in install scripts, backdoored packages). Python: exec()/eval() (bare or via builtins/__import__) whose argument decodes base64/base32/base85 (b64decode, decodebytes, a2b_base64), hex (bytes.fromhex, unhexlify), codecs.decode, zlib/bz2/lzma/gzip.decompress or marshal.loads, inline or through a variable assigned from such a decoder (one intermediate assignment allowed) within 15 lines above. JavaScript/TypeScript: eval(), new Function()/Function(), vm.runInThisContext/runInNewContext/runInContext/new vm.Script and child_process exec/execSync whose argument is atob(), Buffer.from(..., 'base64'|'hex'), String.fromCharCode() or a Base64.decode(), inline or through such a variable. Not reported: decoding data that is parsed, written or returned rather than executed (JSON.parse(atob(..)), ast.literal_eval), a regex's .exec(), executing a constant or an unrelated variable, a decoder applied to request data or to an encoder's output (an encode/decode round trip: the executed value is the program's own input, not an embedded payload; reported by VNX-94 or VNX-PY-002/VNX-NODE-002), and the pattern inside comments or string literals. On a Python exec/eval of a decoded blob this rule owns the line; VNX-PY-002 does not report it.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-506/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [506],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["embedded-malicious", "obfuscation", "dropper", "cwe-506"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
	endswith(path, ext)
}

_sink := {
	"py": `(?:^|[^\w.])(?:exec|eval)\s*\(|\bbuiltins\.(?:exec|eval)\s*\(|__import__\(\s*["']builtins["']\s*\)\.(?:exec|eval)\s*\(`,
	"js": `(?:^|[^\w.$])eval\s*\(|(?:^|[^\w.$])(?:new\s+)?Function\s*\(|\bvm\.(?:runIn\w*Context|Script)\s*\(|\bnew\s+vm\.Script\s*\(|child_process["']?\)?\s*\.\s*exec(?:Sync)?\s*\(|(?:^|[^\w.$])execSync\s*\(`,
}

_decoder := {
	"py": `\b(?:b64decode|b32decode|b16decode|b85decode|a85decode|urlsafe_b64decode|decodebytes|decodestring|a2b_base64|a2b_hex|unhexlify|fromhex|marshal\.loads|zlib\.decompress|bz2\.decompress|lzma\.decompress|gzip\.decompress|codecs\.decode)\s*\(`,
	"js": `\batob\s*\(|\bBuffer\.from\s*\([^)]*["'](?:base64|hex|base64url)["']|\bString\.fromCharCode\s*\(|\bBase64\.decode\s*\(|\bbase64\.decode\s*\(`,
}

# Gate a whole file before splitting it: it names a decoder at all.
_gate("py", content) if regex.match(`b64decode|b32decode|b85decode|a85decode|decodebytes|decodestring|a2b_|unhexlify|fromhex|marshal\.loads|decompress|codecs\.decode`, content)

_gate("js", content) if regex.match(`atob\(|base64|["']hex["']|fromCharCode|Base64\.decode`, content)

# The decoder must sit inside the call the sink opens, a short distance
# after it: a minified bundle that mentions eval and atob on one line is not
# this shape.
_inline(lang, c) if {
	re := concat("", [`(?:`, _sink[lang], `)[^;]{0,160}?(?:`, _decoder[lang], `)`])
	regex.match(re, c)
}

# Python: string literals blanked, so a sink named in a message is text.
# JavaScript keeps literals (Buffer.from's 'base64' is one) and blanks only
# those that themselves spell a sink call.
_code(lang, line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`) if lang == "py"

_code(lang, line) := regex.replace(line, `"(?:[^"\\]|\\.)*(?:exec|eval|Function)\s*\((?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*(?:exec|eval|Function)\s*\((?:[^'\\]|\\.)*'`, `""`) if lang == "js"

# What a decoder reads when the decoded value is the program's own data and
# not an embedded payload: an encoder's output (an encode/decode round trip)
# or the request. Running that is code injection (VNX-94) or a plain dynamic
# eval (VNX-PY-002, VNX-NODE-002), not a dropper.
_plain := {
	"py": `\b(?:b64encode|b32encode|b16encode|b85encode|a85encode|urlsafe_b64encode|encodebytes|encodestring|b2a_base64|b2a_hex|hexlify|marshal\.dumps|zlib\.compress|bz2\.compress|lzma\.compress|gzip\.compress|codecs\.encode)\s*\(|\.hex\(\)|\brequest\.(?:args|form|values|json|get_json|data|cookies|COOKIES|headers|GET|POST|body|query_params|stream|files)\b`,
	"js": `\bbtoa\s*\(|\.toString\s*\(\s*["'](?:base64|hex|base64url)["']|\bBase64\.encode\s*\(|\bbase64\.encode\s*\(|\b(?:req|request)\.(?:query|body|params|headers|cookies)\b|\bctx\.(?:query|params|request\.body)\b`,
}

# The decoder's first argument, when it is a bare name.
_decoder_arg := {
	"py": concat("", [`(?:`, _decoder.py, `)\s*([A-Za-z_]\w*)\s*[,)]`]),
	"js": `\b(?:atob|Buffer\.from|Base64\.decode|base64\.decode)\s*\(\s*([A-Za-z_]\w*)\s*[,)]`,
}

_plain_input(lang, lines, j, pc) if regex.match(concat("", [`(?:`, _decoder[lang], `)[^;]{0,120}?(?:`, _plain[lang], `)`]), pc)

_plain_input(lang, lines, j, pc) if {
	m := regex.find_all_string_submatch_n(_decoder_arg[lang], pc, 1)
	count(m) > 0
	n := m[0][1]
	j > 0
	some k in numbers.range(max([0, j - 15]), j - 1)
	src := lines[k]
	not helpers.is_comment_line(src)
	helpers.assigned_ident(src) == n
	regex.match(_plain[lang], src)
}

_reported(lang, lines, i, c) if {
	_inline(lang, c)
	not regex.match(concat("", [`(?:`, _decoder[lang], `)[^;]{0,120}?(?:`, _plain[lang], `)`]), c)
}

# A variable assigned from a decoder in the 15 lines above reaches the sink,
# directly or through one intermediate assignment.
_reported(lang, lines, i, c) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_decoder[lang], _code(lang, prev))
	not _plain_input(lang, lines, j, _code(lang, prev))
	v := helpers.assigned_ident(prev)
	_sink_arg_mentions(lang, lines, j, i, c, v)
}

_sink_arg_mentions(lang, lines, j, i, c, v) if {
	regex.match(concat("", [`(?:`, _sink[lang], `)[^;]{0,80}?\b`, v, `\b`]), c)
}

_sink_arg_mentions(lang, lines, j, i, c, v) if {
	i - 1 >= j + 1
	some k in numbers.range(j + 1, i - 1)
	mid := lines[k]
	not helpers.is_comment_line(mid)
	regex.match(concat("", [`\b`, v, `\b`]), mid)
	w := helpers.assigned_ident(mid)
	regex.match(concat("", [`(?:`, _sink[lang], `)[^;]{0,80}?\b`, w, `\b`]), c)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_gate(lang, content)
	not endswith(path, ".min.js")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`exec|eval|Function|vm\.|execSync`, line)
	not helpers.is_comment_line(line)
	c := _code(lang, line)
	regex.match(_sink[lang], c)
	_reported(lang, lines, i, c)
	finding := {
		"rule_id": metadata.id,
		"message": "An encoded payload is decoded and executed; this is the loader pattern of embedded malicious code. Remove it, or ship the code in plain source",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

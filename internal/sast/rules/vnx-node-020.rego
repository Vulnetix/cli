package vulnetix.rules.vnx_node_020

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-020",
	"name": "Deprecated crypto.createCipher/createDecipher without IV",
	"description": "Node's crypto.createCipher() or crypto.createDecipher() is called. Both derive the key and IV from the password with a single unsalted MD5 pass (EVP_BytesToKey), so every message encrypted under one password uses the same IV: CTR, GCM and CCM lose confidentiality and integrity outright, and CBC leaks equal prefixes. Both were deprecated in Node 10 and removed in Node 22. Reported, in JavaScript and TypeScript: the call through crypto or any name bound to the crypto/node:crypto module (require, default or namespace import), including a member access continued on the next line (nodeCrypto on one line, .createCipher(...) on the next), require('crypto').createCipher(...) inline, and createCipher/createDecipher imported from it by name (including an `as` alias). Not reported: createCipheriv()/createDecipheriv(), node-forge's forge.cipher.createCipher() (which takes its IV in start()), a method or function of the same name defined in the program, comments and string literals. Use createCipheriv() with a key from scrypt/pbkdf2 and a random IV from crypto.randomBytes().",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-020/",
	"languages": ["javascript", "typescript"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [330],
	"capec": ["CAPEC-20"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "weak-iv", "encryption", "node"],
}

_is_js(path) if regex.match(`\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)

_mod := `['"](?:node:)?crypto['"]`

_alias_res := [
	concat("", [`\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*`, _mod, `\s*\)`]),
	concat("", [`\bimport\s+(?:\*\s+as\s+)?(\w+)\s*(?:,\s*\{[^}]*\}\s*)?from\s+`, _mod]),
	concat("", [`\bimport\s+(\w+)\s*=\s*require\(\s*`, _mod]),
]

_named_res := [
	concat("", [`\bimport\s*(?:\w+\s*,\s*)?\{([^}]*)\}\s*from\s*`, _mod]),
	concat("", [`\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*`, _mod]),
]

_strip(line) := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, `""`)

_aliases(lines) := {a |
	some l in lines
	contains(l, "crypto")
	not helpers.is_comment_line(l)
	some re in _alias_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	a := m[1]
} | {"crypto"}

_named(lines) := {local |
	some l in lines
	contains(l, "crypto")
	not helpers.is_comment_line(l)
	some re in _named_res
	some m in regex.find_all_string_submatch_n(re, l, -1)
	some item in split(m[1], ",")
	parts := regex.split(`\s+as\s+|\s*:\s*`, trim_space(item))
	parts[0] in {"createCipher", "createDecipher"}
	local := trim_space(parts[count(parts) - 1])
}

_sink_re(aliases, named) := concat("|", array.concat(
	[concat("", [`\b`, a, `\s*\.\s*create(?:Cipher|Decipher)\s*\(`]) | some a in aliases],
	array.concat(
		[concat("", [`(?:^|[^.\w])`, n, `\s*\(`]) | some n in named],
		[`__REQ_CRYPTO__\s*\.\s*create(?:Cipher|Decipher)\s*\(`],
	),
))

# require('crypto') stays recognisable (as a marker) after string stripping.
_strip_except_crypto(line) := _strip(regex.replace(line, `require\(\s*['"](?:node:)?crypto['"]\s*\)`, "__REQ_CRYPTO__"))

_definition(line) if regex.match(`^\s*(?:export\s+)?(?:async\s+)?(?:function\s+|(?:public|private|protected|static)\s+)*create(?:Cipher|Decipher)\s*\([^)]*\)\s*(?::\s*[\w<>\[\]]+\s*)?\{`, line)

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(`create(?:Cipher|Decipher)\b`, content)
	lines := split(content, "\n")
	re := _sink_re(_aliases(lines), _named(lines))
	some i, line in lines
	regex.match(`(?i)cipher\s*\(`, line)
	not helpers.is_comment_line(line)
	not _definition(line)
	regex.match(re, _strip_except_crypto(line))
	finding := {
		"rule_id": metadata.id,
		"message": "crypto.createCipher()/createDecipher() derive the key and IV from the password with one MD5 pass, so every message reuses the same IV; use createCipheriv()/createDecipheriv() with a random IV from crypto.randomBytes()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The member access continues on the next line: nodeCrypto
#     .createCipher(...)
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	regex.match(`(?m)^\s*\.\s*create(?:Cipher|Decipher)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	i > 0
	regex.match(`^\s*\.\s*create(?:Cipher|Decipher)\s*\(`, line)
	prev := _strip_except_crypto(lines[i - 1])
	not helpers.is_comment_line(lines[i - 1])
	some a in _aliases(lines) | {"__REQ_CRYPTO__"}
	regex.match(concat("", [`\b`, a, `\s*$`]), prev)
	finding := {
		"rule_id": metadata.id,
		"message": "crypto.createCipher()/createDecipher() derive the key and IV from the password with one MD5 pass, so every message reuses the same IV; use createCipheriv()/createDecipheriv() with a random IV from crypto.randomBytes()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

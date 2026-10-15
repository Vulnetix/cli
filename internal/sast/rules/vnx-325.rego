# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_325

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-325",
	"name": "Missing Cryptographic Step",
	"description": "AES is used in an unauthenticated mode (CBC, CTR, CFB, OFB, PCBC) in a file that never computes a MAC or signature, so the integrity step of encrypt-then-MAC is missing: ciphertext can be altered undetected, and CBC decryption without a MAC is a padding oracle. Reported: Java/Kotlin transformation strings \"AES/CBC/...\", \"AES/CTR/...\", \"AES/CFB8/...\", \"AES/OFB/...\" (in Cipher.getInstance or a constant); Python PyCryptodome AES.new(..., AES.MODE_CBC|CTR|CFB|OFB|OPENPGP) and cryptography Cipher(algorithms.AES(key), modes.CBC|CTR|CFB|CFB8|OFB(...)); Node.js createCipheriv/createDecipheriv with 'aes-*-cbc|ctr|cfb|ofb' or the bare OpenSSL aliases 'aes128'/'aes192'/'aes256' (which are CBC), on the call line or as the first argument of a call wrapped onto the next line; PHP 'aes-256-cbc'-style literals (on the call or in a constant) in a file that calls openssl_encrypt/openssl_decrypt; Ruby OpenSSL::Cipher.new(\"aes-256-cbc\"), OpenSSL::Cipher::AES.new(128, :CBC) and a mode literal in a file that builds an OpenSSL::Cipher. A mode built at runtime or read from a config file is not seen. Not reported: AEAD modes (GCM, CCM, EAX, SIV, OCB, ChaCha20-Poly1305), any file that also computes an HMAC/CMAC/Poly1305 or a signature (Mac.getInstance, hmac.new, createHmac, hash_hmac, OpenSSL::HMAC, Signature, sign(), openssl_sign), ECB and bare \"AES\" (VNX-CRYPTO-003), the mode names in comments or Python string literals, and test files. A MAC computed in another file is not seen, so review a finding against its caller. C# is not covered: RijndaelManaged and Aes.Create default to CBC without naming the mode.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-325/",
	"languages": ["java", "kotlin", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [325],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["missing-crypto-step", "cwe-325", "crypto", "unauthenticated-encryption"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

# per-language: a cheap content gate, the sink pattern
_lang(path) := {
	"gate": `(?i)"AES/(CBC|CTR|CFB\d*|OFB|PCBC)/`,
	"sink": `(?i)"AES/(CBC|CTR|CFB\d*|OFB|PCBC)/`,
	"strip": false,
} if {
	some ext in {".java", ".kt"}
	endswith(path, ext)
}

_lang(path) := {
	"gate": `AES\.MODE_(CBC|CTR|CFB|OFB|OPENPGP)\b|algorithms\.AES\b`,
	"sink": `\bAES\.MODE_(CBC|CTR|CFB|OFB|OPENPGP)\b|\bmodes\.(CBC|CTR|CFB8?|OFB)\s*\(`,
	"strip": true,
} if endswith(path, ".py")

_lang(path) := {
	"gate": `(?i)['"\x60](aes-?(128|192|256)?-(cbc|ctr|cfb\d*|ofb)|aes(128|192|256))['"\x60]`,
	"sink": `(?i)create(De)?[Cc]ipheriv\s*\(\s*['"\x60](aes-?(128|192|256)?-(cbc|ctr|cfb\d*|ofb)|aes(128|192|256))['"\x60]|^\s*['"\x60]aes-?(128|192|256)?-(cbc|ctr|cfb\d*|ofb)['"\x60]\s*,`,
	"strip": false,
} if {
	some ext in _js_exts
	endswith(path, ext)
}

# PHP: openssl_encrypt/openssl_decrypt with the mode as a literal, on the
# call line or held in a constant/variable in the same file.
_lang(path) := {
	"gate": `openssl_(en|de)crypt\s*\(`,
	"sink": `(?i)['"]aes-(128|192|256)-(cbc|ctr|cfb\d*|ofb)['"]`,
	"strip": false,
} if endswith(path, ".php")

# Ruby: OpenSSL::Cipher.new("aes-256-cbc"), OpenSSL::Cipher::AES.new(128, :CBC),
# or the mode literal returned by a helper in a file that builds the cipher.
_lang(path) := {
	"gate": `OpenSSL::Cipher`,
	"sink": `(?i)['"]aes-?(128|192|256)-(cbc|ctr|cfb\d*|ofb)['"]|OpenSSL::Cipher::AES(128|192|256)?\.new\([^)]*:(CBC|CTR|CFB\d*|OFB)\b`,
	"strip": false,
} if endswith(path, ".rb")

# Any integrity step in the file: a MAC, an AEAD tag or a signature.
_mac_re := `(?i)hmac|\bMac\.getInstance|\bcmac\b|poly1305|\bSignature\.getInstance|\.sign\s*\(|createSign\s*\(|\bhashes\.HMAC|\bsign_detached|\bverify_tag\b|openssl_sign\s*\(`

_strip_strings(line) := regex.replace(line, `"[^"]*"|'[^']*'`, `""`)

_matches(line, true, sink) if regex.match(sink, _strip_strings(line))

_matches(line, false, sink) if regex.match(sink, line)

# cryptography's modes.X(...) is only AES when the file builds algorithms.AES
_py_mode_ok(path, content, line) if not endswith(path, ".py")

_py_mode_ok(path, _, line) if {
	endswith(path, ".py")
	contains(line, "AES.MODE_")
}

_py_mode_ok(path, content, line) if {
	endswith(path, ".py")
	not contains(line, "AES.MODE_")
	contains(content, "algorithms.AES")
}

# A mode string alone on its line is only the first argument of a call that
# opened on the line above: createCipheriv(\n  'aes-128-ctr',
# (Ruby and PHP report the bare literal: it is a mode constant or helper return.)
_js_arg_ok(path, _, _, _) if {
	some ext in {".rb", ".php"}
	endswith(path, ext)
}

_js_arg_ok(path, _, _, line) if {
	not endswith(path, ".rb")
	not endswith(path, ".php")
	not regex.match(`^\s*['"\x60]aes`, line)
}

_js_arg_ok(path, lines, i, line) if {
	not endswith(path, ".rb")
	not endswith(path, ".php")
	regex.match(`^\s*['"\x60]aes`, line)
	i > 0
	regex.match(`create(De)?[Cc]ipheriv\s*\(\s*$`, lines[i - 1])
}

findings contains finding if {
	some path, content in input.file_contents
	l := _lang(path)
	regex.match(l.gate, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	not regex.match(_mac_re, helpers.code_text(lines))
	some i, line in lines
	not helpers.is_comment_line(line)
	_matches(line, l.strip, l.sink)
	_py_mode_ok(path, content, line)
	_js_arg_ok(path, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "AES in an unauthenticated mode with no MAC in this file: the ciphertext is not integrity-protected (CBC decryption becomes a padding oracle). Use AES-GCM or ChaCha20-Poly1305, or encrypt-then-MAC with HMAC-SHA256",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

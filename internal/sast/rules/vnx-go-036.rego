package vulnetix.rules.vnx_go_036

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-036",
	"name": "Use of ECB block mode",
	"description": "Go code encrypts or decrypts in ECB (Electronic Codebook) mode, which encrypts equal plaintext blocks to equal ciphertext blocks and carries no integrity, so records leak their structure and blocks can be cut and pasted. Reported: a call to NewECBEncrypter/NewECBDecrypter (the crypt2go ecb package or a local implementation of the same name), and ECB written by hand: a cipher.Block's Encrypt/Decrypt called on slices of the data inside a loop, where the block came from aes/des/blowfish/twofish/cast5/sm4 NewCipher, des.NewTripleDESCipher or a cipher.Block parameter, and the loop body does no XOR chaining. Not reported: GCM, CBC, CTR and the other crypto/cipher modes, hand-written CBC/CTR loops (they XOR each block with the previous ciphertext or a keystream), a single-block Encrypt outside a loop (CMAC subkeys, key wrapping), the word ECB in identifiers, strings, error messages, comments or a guard that rejects it, and test files (known-answer vectors are ECB by definition).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-036/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-32"],
	"attack_technique": ["T1068.003"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["cryptography", "ecb", "block-mode", "weak-crypto"],
}

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

_ctor := `\b(?:aes|des|blowfish|twofish|cast5|sm4|camellia)\.New(?:TripleDES)?Cipher\(`

_indent(l) := count(l) - count(trim_left(l, " \t"))

# Names that hold a cipher.Block in this file.
_blocks(lines, content) := {v |
	some l in lines
	regex.match(_ctor, l)
	v := helpers.assigned_first(l)
} | {v |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s+cipher\.Block\b`, content, -1)
	v := m[1]
}

# The innermost enclosing for loop within fifteen lines above, still open.
_loop(lines, i) := f if {
	ic := _indent(lines[i])
	fs := [j |
		some j in numbers.range(max([0, i - 15]), i - 1)
		regex.match(`^\s*for\b`, lines[j])
		_indent(lines[j]) < ic
		not _closed(lines, j, i)
	]
	count(fs) > 0
	f := max(fs)
}

_closed(lines, j, i) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	regex.match(`^\s*\}`, lines[k])
	_indent(lines[k]) <= _indent(lines[j])
}

# The loop chains blocks (CBC) or applies a keystream (CTR, OFB, CFB).
_chained(lines, f, i) if {
	some k in numbers.range(f, min([count(lines) - 1, max([f + 10, i + 6])]))
	regex.match(`\^|(?i:xor)`, _code(lines[k]))
}

_hit(_, _, code, _) if {
	regex.match(`(?i:\bnewECB(?:En|De)crypter)\(`, code)
	not regex.match(`^\s*func\b`, code)
}

_hit(lines, i, code, blocks) if {
	ms := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.(?:Encrypt|Decrypt)\(([^)]*)\)`, code, -1)
	some m in ms
	m[1] in blocks
	contains(m[2], "[")
	f := _loop(lines, i)
	not _chained(lines, f, i)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?i)newECB(?:En|De)crypter\(|\.(?:Encrypt|Decrypt)\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	blocks := _blocks(lines, content)
	some i, line in lines
	regex.match(`(?i)ecb|crypt\(`, line)
	not helpers.is_comment_line(line)
	_hit(lines, i, _code(line), blocks)
	finding := {
		"rule_id": metadata.id,
		"message": "ECB block mode: equal plaintext blocks encrypt to equal ciphertext and nothing protects integrity; use AES-GCM (cipher.NewGCM) or ChaCha20-Poly1305",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_java_020

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-020",
	"name": "Java static IV reuse in block cipher",
	"description": "A block-cipher IV or GCM nonce is fixed in the source, so every message encrypted under the same key reuses it: CBC leaks equal plaintext prefixes, and CTR and GCM leak the XOR of plaintexts (GCM also loses authentication). Reported: new IvParameterSpec(iv) and new GCMParameterSpec(tagLen, iv) where iv is a string literal (.getBytes()), a Base64/hex decode of a literal, a byte-array literal, or a zero-filled new byte[n] passed inline; a byte[]/String field or constant initialised with such a literal (including a multi-line byte-array initialiser), directly or through one .getBytes() assignment; a static final byte[] allocated with new byte[n] that the file never fills with nextBytes(); and a local new byte[n] handed to the spec within 15 lines with nothing touching it in between. Not reported: an IV filled by SecureRandom.nextBytes(), read from the ciphertext (ByteBuffer.get, Arrays.copyOfRange), taken from cipher.getIV() or passed in as a parameter; constants that are only sizes or names; and the pattern in comments or string literals. Hardcoded keys are VNX-JAVA-019's concern.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-020/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [329],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "iv", "cbc", "java"],
}

_lit := `"(?:[^"\\]|\\.)+"`

# An expression whose value is fixed in the source.
_literal_expr := concat("", [
	`^(`, _lit, `(\s*\.\s*(getBytes|toCharArray)\s*\([^)]*\))?`,
	`|[\w.()]*\.\s*(decode|decodeBase64|decodeHex|parseHexBinary)\s*\(\s*`, _lit, `\s*(,[^)]*)?\)`,
	`|(new\s+byte\s*\[\s*\]\s*)?\{\s*(\(byte\)\s*)?-?(0[xX][0-9a-fA-F]+|[0-9]+)`,
	`)\s*[,;)}]`,
])

# Passed inline, a zero-filled allocation is a fixed (all-zero) IV too.
_inline_fixed := `^new\s+byte\s*\[\s*\w+\s*\]\s*\)`

_decl_re := `^\s*(?:(?:public|private|protected|static|final)\s+)*(?:String|byte\s*\[\s*\]|var)\s+([A-Za-z_]\w*)\s*=\s*(.*)$`

_alloc_re := `^\s*(?:final\s+)?byte\s*\[\s*\]\s+([A-Za-z_]\w*)\s*=\s*new\s+byte\s*\[[^\]]+\]\s*;`

_strip_strings(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

_lit_names(lines) := {m[1] |
	some l in lines
	contains(l, "=")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_decl_re, l, 1)
	_fixed_init(trim_space(m[2]))
}

_fixed_init(v) if regex.match(_literal_expr, v)

# A byte-array initialiser that opens on this line and lists its bytes below.
_fixed_init(v) if v == "{"

# static final byte[] NONCE = new byte[12]; never filled anywhere in the file.
_zero_consts(lines, content) := {m[1] |
	some l in lines
	contains(l, "static")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`\bstatic\b[^=]*\bbyte\s*\[\s*\]\s+([A-Za-z_]\w*)\s*=\s*new\s+byte\s*\[[^\]]+\]\s*;`, l, 1)
	not regex.match(concat("", [`nextBytes\s*\(\s*(this\.)?`, m[1], `\b|\b`, m[1], `\s*\[[^\]]*\]\s*=[^=]|arraycopy\s*\([^;]*,\s*`, m[1], `\s*,`]), content)
}

_hop_names(lines, base) := {m[1] |
	some l in lines
	contains(l, "getBytes")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(_decl_re, l, 1)
	some h in regex.find_all_string_submatch_n(`^(?:this\.)?([A-Za-z_]\w*)\s*\.\s*getBytes\s*\(`, trim_space(m[2]), 1)
	h[1] in base
}

_names(lines, content) := (n | _hop_names(lines, n)) | _zero_consts(lines, content) if n := _lit_names(lines)

_sink_re := `new\s+IvParameterSpec\s*\(\s*|new\s+GCMParameterSpec\s*\(\s*[^,()]+,\s*`

_name_arg := `^(?:this\.)?([A-Za-z_]\w*)\s*[,)]`

_stmt(lines, i) := concat(" ", [lines[k] | some k in numbers.range(i, min([count(lines) - 1, i + 2]))])

_fixed(_, _, _, _, rest) if regex.match(_literal_expr, rest)

_fixed(_, _, _, _, rest) if regex.match(_inline_fixed, rest)

_fixed(lines, content, _, _, rest) if {
	some m in regex.find_all_string_submatch_n(_name_arg, rest, 1)
	m[1] in _names(lines, content)
}

# A local zero-filled buffer that nothing writes before it becomes the IV.
_fixed(lines, _, i, _, rest) if {
	some m in regex.find_all_string_submatch_n(_name_arg, rest, 1)
	v := m[1]
	some j in numbers.range(max([0, i - 15]), i - 1)
	some a in regex.find_all_string_submatch_n(_alloc_re, lines[j], 1)
	a[1] == v
	not _touched(lines, j, i, v)
}

_touched(lines, j, i, v) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	regex.match(concat("", [`\b`, v, `\b`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`IvParameterSpec|GCMParameterSpec`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`IvParameterSpec|GCMParameterSpec`, line)
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _strip_strings(line))
	stmt := regex.replace(_stmt(lines, i), `//[^"\n]*$`, "")
	some m in regex.find_all_string_submatch_n(concat("", [`(?:`, _sink_re, `)(.*)`]), stmt, -1)
	_fixed(lines, content, i, line, m[1])
	finding := {
		"rule_id": metadata.id,
		"message": "Initialisation vector or nonce is fixed in the source and reused for every encryption; generate a fresh one per message with SecureRandom.nextBytes() and send it with the ciphertext",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

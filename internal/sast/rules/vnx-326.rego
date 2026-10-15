# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_326

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-326",
	"name": "Inadequate Encryption Strength (undersized DSA, DH, EC or symmetric key)",
	"description": "A key is generated too small to resist attack. Reported: DSA and Diffie-Hellman keys or parameters below 2048 bits (Java KeyPairGenerator.getInstance(\"DSA\"|\"DH\"|\"DiffieHellman\") then initialize(N) on that generator; Python cryptography dsa.generate_private_key(key_size=N) and dh.generate_parameters(..., key_size=N), PyCryptodome DSA.generate(N); Go dsa.L1024N160; Node.js generateKeyPair(Sync)('dsa'|'dh', { modulusLength|primeLength: N }), createDiffieHellman(N) and the 768-1536-bit getDiffieHellman('modp1'|'modp2'|'modp5') groups); AES keys below 128 bits (Java KeyGenerator.getInstance(\"AES\") then init(N)); elliptic curves under 224 bits (secp112/128/160/192, prime192v*, sect113-193, brainpoolP160/192, P-192) in Java ECGenParameterSpec or KeyPairGenerator.getInstance(\"EC\") then initialize(N < 224), Python ec.SECP192R1() and friends, PyCryptodome ECC.generate(curve=\"P-192\"), Node namedCurve/createECDH; RSA, DSA and DH keys below 2048 bits in Ruby OpenSSL::PKey::RSA/DSA/DH.new|generate(N) and PHP openssl_pkey_new 'private_key_bits' => N. Not reported: sizes of 2048 bits (128 for AES) and above, sizes from a variable or configuration, init()/initialize() on objects that are not such a generator, RSA in Python, Go, Java and Node.js (VNX-CRYPTO-006 covers those), broken ciphers such as DES and RC4 (VNX-CRYPTO-004), comments, string literals and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-326/",
	"languages": ["go", "java", "kotlin", "node", "php", "python", "ruby"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [326],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "key-size", "cwe-326"],
}

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_weak_curve := `(secp(112|128|160|192)[rk][12]|prime192v[123]|sect(113|131|163|193)[rk][12]|brainpoolP(160|192)[rt]1|P-192|nistp192)`

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_msg := "Key size or curve below the strength floor (2048-bit DSA/DH/RSA, 128-bit AES, 224-bit curves); use 3072-bit DSA/DH/RSA, AES-256, or P-256/X25519"

_strip(line) := regex.replace(line, `"[^"]*"|'[^']*'`, `""`)

# ── numeric sinks: [extension set, regex with the size in group 1, floor] ──

_num_sinks := [
	{"exts": {".py"}, "gate": "generate_", "re": `\bdsa\.generate_private_key\(\s*(?:key_size\s*=\s*)?(\d+)`, "floor": 2048},
	{"exts": {".py"}, "gate": "generate_", "re": `\bdh\.generate_parameters\([^)]*?key_size\s*=\s*(\d+)`, "floor": 2048},
	{"exts": {".py"}, "gate": "generate_", "re": `\bdh\.generate_parameters\(\s*\w+\s*,\s*(\d+)`, "floor": 2048},
	{"exts": {".py"}, "gate": "DSA.generate", "re": `\bDSA\.generate\(\s*(?:bits\s*=\s*)?(\d+)`, "floor": 2048},
	{"exts": _js_exts, "gate": "createDiffieHellman", "re": `\bcreateDiffieHellman\(\s*(\d+)\s*[,)]`, "floor": 2048},
	{"exts": {".php"}, "gate": "private_key_bits", "re": `['"]private_key_bits['"]\s*=>\s*(\d+)`, "floor": 2048},
	{"exts": {".rb"}, "gate": "OpenSSL::PKey::", "re": `\bOpenSSL::PKey::(?:RSA|DSA|DH)\.(?:new|generate)\(?\s*(\d+)\b`, "floor": 2048},
]

findings contains finding if {
	some path, content in input.file_contents
	some s in _num_sinks
	some ext in s.exts
	endswith(path, ext)
	contains(content, s.gate)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, s.gate)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(s.re, line, 1)
	count(m) > 0
	to_number(m[0][1]) < s.floor
	finding := _finding(path, i, line, _msg)
}

# ── named weak parameters ──────────────────────────────────────────────

_name_sinks := [
	{"exts": {".go"}, "gate": "dsa.L1024", "re": `\bdsa\.L1024N160\b`},
	{"exts": _js_exts, "gate": "getDiffieHellman", "re": `\bgetDiffieHellman\(\s*['"\x60]modp(1|2|5)['"\x60]`},
	{"exts": _js_exts, "gate": "namedCurve", "re": concat("", [`\bnamedCurve\s*:\s*['"\x60]`, _weak_curve, `['"\x60]`])},
	{"exts": _js_exts, "gate": "createECDH", "re": concat("", [`\bcreateECDH\(\s*['"\x60]`, _weak_curve, `['"\x60]`])},
	{"exts": {".java", ".kt"}, "gate": "ECGenParameterSpec", "re": concat("", [`\bECGenParameterSpec\(\s*"`, _weak_curve, `"`])},
	{"exts": {".py"}, "gate": "ec.", "re": `\bec\.(SECP192R1|SECT163K1|SECT163R2)\s*\(`},
	{"exts": {".rb"}, "gate": "OpenSSL::PKey::EC", "re": concat("", [`\bOpenSSL::PKey::EC\.(new|generate)\(?\s*['"]`, _weak_curve, `['"]`])},
	{"exts": {".py"}, "gate": "ECC.generate", "re": concat("", [`\bECC\.generate\([^)]*\bcurve\s*=\s*['"](?i:`, _weak_curve, `|p192|NIST P-192)['"]`])},
]

findings contains finding if {
	some path, content in input.file_contents
	some s in _name_sinks
	some ext in s.exts
	endswith(path, ext)
	contains(content, s.gate)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, s.gate)
	not helpers.is_comment_line(line)
	regex.match(s.re, line)
	finding := _finding(path, i, line, _msg)
}

# ── Node.js: generateKeyPair('dsa'|'dh', { modulusLength: N }), one line or wrapped ──

findings contains finding if {
	some path, content in input.file_contents
	some ext in _js_exts
	endswith(path, ext)
	contains(content, "generateKeyPair")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\b(?:modulusLength|primeLength)\s*:\s*(\d+)`, line, 1)
	count(m) > 0
	to_number(m[0][1]) < 2048
	window := helpers.code_window(lines, i, 3, 0)
	regex.match(`generateKeyPair(?:Sync)?\(\s*['"\x60](dsa|dh|dhx)['"\x60]`, window)
	not regex.match(`generateKeyPair(?:Sync)?\(\s*['"\x60](rsa|rsa-pss|ec)['"\x60][^\n]*$`, window)
	finding := _finding(path, i, line, _msg)
}

# ── Python: key_size=N on its own line inside a wrapped dsa/dh call ──

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "generate_")
	contains(content, "key_size")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "key_size")
	m := regex.find_all_string_submatch_n(`^\s*key_size\s*=\s*(\d+)\s*[,)]?\s*$`, line, 1)
	count(m) > 0
	to_number(m[0][1]) < 2048
	window := helpers.code_window(lines, i, 3, 0)
	regex.match(`\b(dsa\.generate_private_key|dh\.generate_parameters)\(`, window)
	finding := _finding(path, i, line, _msg)
}

# ── Java/Kotlin: initialize(N)/init(N) on a DSA/DH KeyPairGenerator or AES KeyGenerator ──

_gen_vars(content, re) := {m[1] | some m in regex.find_all_string_submatch_n(re, content, -1)}

_java_gens := [
	{"gate": "KeyPairGenerator", "decl": `(\w+)\s*=\s*(?:java\.security\.)?KeyPairGenerator\.getInstance\(\s*"(?:DSA|DH|DiffieHellman)"`, "call": "initialize", "floor": 2048},
	{"gate": "KeyPairGenerator", "decl": `(\w+)\s*=\s*(?:java\.security\.)?KeyPairGenerator\.getInstance\(\s*"(?:EC|ECDSA|ECDH)"`, "call": "initialize", "floor": 224},
	{"gate": "KeyGenerator", "decl":`(\w+)\s*=\s*(?:javax\.crypto\.)?KeyGenerator\.getInstance\(\s*"AES"`, "call": "init", "floor": 128},
]

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	some g in _java_gens
	contains(content, g.gate)
	not helpers.is_test_path(path)
	vars := _gen_vars(content, g.decl)
	count(vars) > 0
	lines := split(content, "\n")
	some i, line in lines
	contains(line, g.call)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`\b(\w+)\.`, g.call, `\(\s*(\d+)\s*[,)]`]), _strip(line), 1)
	count(m) > 0
	m[0][1] in vars
	to_number(m[0][2]) < g.floor
	finding := _finding(path, i, line, _msg)
}

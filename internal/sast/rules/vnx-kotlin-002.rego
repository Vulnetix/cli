package vulnetix.rules.vnx_kotlin_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-KOTLIN-002",
	"name": "Kotlin RSA, DSA or DH key smaller than 2048 bits",
	"description": "An RSA, DSA or Diffie-Hellman key pair is generated with a modulus smaller than 2048 bits, which today's factoring and discrete-log computations can break. Reported in Kotlin (.kt, .kts): KeyPairGenerator.initialize(n) and initialize(n, random) on a generator obtained from KeyPairGenerator.getInstance(\"RSA\"/\"DSA\"/\"DH\"/\"DiffieHellman\"/KeyProperties.KEY_ALGORITHM_RSA), through a variable or inside apply/run/also/with (the getInstance chain may span several lines); init(n) on an AlgorithmParameterGenerator for \"DSA\"/\"DH\" domain parameters; RSAKeyGenParameterSpec(n, ...); setKeySize(n) on an Android KeyGenParameterSpec.Builder that feeds an RSA KeyPairGenerator or on the legacy KeyPairGeneratorSpec.Builder (RSA by default); and Bouncy Castle RSAKeyGenerationParameters(e, random, n, certainty). The size may be a literal, a constant or a parameter default assigned exactly once in the file, and may sit on a continuation line or after an inline block comment. Not reported: sizes of 2048 or more; a keystore setKeySize under 512 bits (an AES or EC size, whatever generator sits nearby); EC, EdDSA and symmetric (KeyGenerator, AES/HMAC keystore) sizes; a size variable the file assigns more than once or a generator whose algorithm is not visible (a parameter, a variable algorithm name); unrelated initialize()/setKeySize() calls; test code; and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-kotlin-002/",
	"languages": ["kotlin"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [326],
	"capec": ["CAPEC-112"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["crypto", "rsa", "key-size", "kotlin"],
}

_message := "RSA/DSA/DH key generated with fewer than 2048 bits; use at least 2048 bits (3072 or more for long-lived keys) or an elliptic-curve key"

_is_kotlin(path) if endswith(path, ".kt")

_is_kotlin(path) if endswith(path, ".kts")

# Kotlin/Gradle test source sets (src/test, src/androidTest, src/jvmTest,
# src/testFixtures), *Test.kt classes and test-support modules.
_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/[A-Za-z]*[Tt]est[A-Za-z]*/`, path)

_is_test(path) if regex.match(`(Test|Tests|Spec|IT)\.kts?$`, path)

_is_test(path) if regex.match(`(^|/)([\w.]+[-_])?test(s|ing)?([-_][\w.-]+)?/`, path)

# The line with string-literal contents blanked and any trailing comment cut,
# so a call written inside a log message or after // is not code.
_code(line) := regex.replace(regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `/\*.*?\*/`, " "), `//.*$`, "")

# Line i and the next two lines as code, for calls whose arguments wrap.
_joined(lines, i) := concat(" ", [_code(l) | some l in array.slice(lines, i, i + 3)])

# The value of an identifier the file assigns exactly once (a const val, a
# val, a parameter default). Two assignments mean the value depends on the
# path taken, which a line rule cannot know.
_single_value(content, id) := v if {
	re := concat("", [`\b`, id, `\s*(?::\s*[\w.?]+)?\s*=\s*([^=\n][^\n]*)`])
	ms := regex.find_all_string_submatch_n(re, content, -1)
	count(ms) == 1
	v := ms[0][1]
}

_weak_number(txt) if {
	m := regex.find_all_string_submatch_n(`^\s*(\d{1,4})\s*(?:$|[,)\s])`, txt, 1)
	count(m) > 0
	to_number(m[0][1]) < 2048
}

_weak_size(arg, _) if _weak_number(arg)

# A constant, possibly qualified (Limits.RSA_BITS): its last segment is
# resolved in this file.
_weak_size(arg, content) if {
	m := regex.find_all_string_submatch_n(`^(?:[A-Za-z_][\w]*\.)*([A-Za-z_]\w*)$`, arg, 1)
	count(m) > 0
	_weak_number(_single_value(content, m[0][1]))
}

_weak_alg_name := `^\s*"(?i:RSA|RSASSA-PSS|DSA|DH|DiffieHellman)"`

# The text after getInstance( names RSA, DSA or DH: a literal, the Android
# constant, or an identifier assigned such a literal once.
_weak_alg(expr, _) if regex.match(_weak_alg_name, expr)

_weak_alg(expr, _) if regex.match(`^\s*(KeyProperties\.)?KEY_ALGORITHM_RSA\b`, expr)

_weak_alg(expr, content) if {
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*[,)]`, expr, 1)
	count(m) > 0
	id := m[0][1]
	id != "KEY_ALGORITHM_EC"
	regex.match(_weak_alg_name, _single_value(content, id))
}

_kpg_alg_expr(txt) := _gen_alg_expr(txt, "KeyPairGenerator")

# The text after <cls>.getInstance( (KeyPairGenerator, or the DSA/DH
# AlgorithmParameterGenerator), the algorithm argument first.
_gen_alg_expr(txt, cls) := e if {
	m := regex.find_all_string_submatch_n(concat("", [`\b`, cls, `\s*\.\s*getInstance\s*\((.*)$`]), txt, 1)
	count(m) > 0
	e := m[0][1]
}

# `x = ...`, `x: KeyPairGenerator = ...` or `x by lazy { ... }`
_assign_re(recv) := concat("", [`\b`, recv, `\s*(?::\s*[\w.?<>]+)?\s*(?:=\s*[^=]|by\s+lazy\b)`])

# The nearest assignment to the receiver above line i.
_recv_assign(lines, i, recv) := j if {
	re := _assign_re(recv)
	js := [k |
		some k in numbers.range(max([0, i - 40]), i - 1)
		contains(lines[k], recv)
		not helpers.is_comment_line(lines[k])
		regex.match(re, lines[k])
	]
	count(js) > 0
	j := max(js)
}

# The variable holds an RSA/DSA/DH generator: its nearest assignment above,
# or, for a property declared further up, its only assignment in the file.
_rsa_var(lines, i, recv, content, cls) if {
	j := _recv_assign(lines, i, recv)
	txt := concat(" ", array.slice(lines, j, j + 2))
	_weak_alg(_gen_alg_expr(txt, cls), content)
}

_rsa_var(lines, i, recv, content, cls) if {
	not _recv_assign(lines, i, recv)
	re := concat("", [`\b`, recv, `\s*(?::\s*[\w.?<>]+)?\s*(?:=|by\s+lazy\b)([^=\n][^\n]*)`])
	ms := regex.find_all_string_submatch_n(re, content, -1)
	count(ms) == 1
	_weak_alg(_gen_alg_expr(ms[0][1], cls), content)
}

_rsa_generator(lines, i, recv, content, cls) if {
	not recv in {"", "it", "this"}
	_rsa_var(lines, i, recv, content, cls)
}

# initialize() inside KeyPairGenerator.getInstance(...).apply/run/also/let { }
# or with(KeyPairGenerator.getInstance(...)) { }, the chain possibly spread
# over the four lines above.
_rsa_generator(lines, i, recv, content, cls) if {
	recv in {"", "it", "this"}
	some k in numbers.range(max([0, i - 4]), i)
	contains(lines[k], cls)
	w := concat(" ", [_code_keep(l) | some l in array.slice(lines, k, i + 1)])
	regex.match(`(\.\s*(apply|run|also|let)\s*\{|\bwith\s*\()`, w)
	_weak_alg(_gen_alg_expr(w, cls), content)
}

# ... or inside with(kpg) { } / kpg.apply { } on a generator variable.
_rsa_generator(lines, i, recv, content, cls) if {
	recv in {"", "it", "this"}
	some k in numbers.range(max([0, i - 3]), i)
	m := regex.find_all_string_submatch_n(`(?:\bwith\s*\(\s*([A-Za-z_]\w*)\s*\)|\b([A-Za-z_]\w*)\s*\.\s*(?:apply|run|also|let))\s*\{`, lines[k], 1)
	count(m) > 0
	v := concat("", [m[0][1], m[0][2]])
	_rsa_var(lines, k, v, content, cls)
}

# A line with a trailing comment cut but string literals kept (the algorithm
# name is a literal).
_code_keep(line) := regex.replace(line, `//[^"]*$`, "")


findings contains finding if {
	some path, content in input.file_contents
	_is_kotlin(path)
	regex.match(`KeyPairGenerator|RSAKeyGen|AlgorithmParameterGenerator`, content)
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`init|RSAKeyGen|setKeySize`, line)
	not helpers.is_comment_line(line)
	_weak_key(lines, i, line, content)
	finding := _finding(path, i, line)
}

# kpg.initialize(1024) / initialize(1024, random) on an RSA/DSA/DH generator
_weak_key(lines, i, line, content) if {
	contains(line, "initialize")
	code := _code(line)
	m := regex.find_all_string_submatch_n(`(?:\b([A-Za-z_]\w*)\s*\.\s*)?\binitialize\s*\(`, code, 1)
	count(m) > 0
	a := regex.find_all_string_submatch_n(`\binitialize\s*\(\s*([^,)]*?)\s*[,)]`, _joined(lines, i), 1)
	count(a) > 0
	_weak_size(a[0][1], content)
	_rsa_generator(lines, i, m[0][1], content, "KeyPairGenerator")
}

# DSA/DH domain parameters: AlgorithmParameterGenerator.getInstance("DH").init(1024)
_weak_key(lines, i, line, content) if {
	contains(line, "init")
	contains(content, "AlgorithmParameterGenerator")
	code := _code(line)
	m := regex.find_all_string_submatch_n(`(?:\b([A-Za-z_]\w*)\s*\.\s*)?\binit\s*\(`, code, 1)
	count(m) > 0
	a := regex.find_all_string_submatch_n(`\binit\s*\(\s*([^,)]*?)\s*[,)]`, _joined(lines, i), 1)
	count(a) > 0
	_weak_size(a[0][1], content)
	_rsa_generator(lines, i, m[0][1], content, "AlgorithmParameterGenerator")
}

# RSAKeyGenParameterSpec(1024, F4)
_weak_key(lines, i, line, content) if {
	contains(line, "RSAKeyGenParameterSpec")
	contains(_code(line), "RSAKeyGenParameterSpec")
	some mm in regex.find_all_string_submatch_n(`\bRSAKeyGenParameterSpec\s*\(\s*([^,)]*?)\s*,`, _joined(lines, i), -1)
	_weak_size(mm[1], content)
}

# Bouncy Castle RSAKeyGenerationParameters(e, random, 1024, certainty)
_weak_key(lines, i, line, content) if {
	contains(line, "RSAKeyGenerationParameters")
	contains(_code(line), "RSAKeyGenerationParameters")
	some mm in regex.find_all_string_submatch_n(`\bRSAKeyGenerationParameters\s*\(\s*[^,]*,\s*[^,]*,\s*([^,)]*?)\s*,`, _joined(lines, i), -1)
	_weak_size(mm[1], content)
}

# Android keystore: .setKeySize(1024) on a builder whose generator is RSA
_weak_key(lines, i, line, content) if {
	contains(line, "setKeySize")
	a := regex.find_all_string_submatch_n(`\.setKeySize\s*\(\s*([^,)]*?)\s*\)`, _code(line), 1)
	count(a) > 0
	_weak_size(a[0][1], content)
	not _sub_rsa_size(a[0][1], content)
	b := _builder_line(lines, i)
	_rsa_builder(lines, b, i, content)
}


# The keystore refuses RSA keys under 512 bits, so a smaller setKeySize is
# an AES (128/192/256) or EC (224/256/384/521) size whose spec happens to sit
# nearest an RSA generator.
_sub_rsa_size(arg, content) if _size_number(arg, content) < 512

_size_number(arg, _) := to_number(m[0][1]) if {
	m := regex.find_all_string_submatch_n(`^\s*(\d{1,4})\b`, arg, 1)
	count(m) > 0
}

_size_number(arg, content) := to_number(m[0][1]) if {
	not regex.match(`^\s*\d`, arg)
	m := regex.find_all_string_submatch_n(`^\s*(\d{1,4})\b`, _single_value(content, regex.replace(arg, `^.*\.`, "")), 1)
	count(m) > 0
}

_builder_line(lines, i) := b if {
	bs := [k |
		some k in numbers.range(max([0, i - 10]), i)
		regex.match(`\b(KeyGenParameterSpec|KeyPairGeneratorSpec)\.Builder\s*\(`, lines[k])
	]
	count(bs) > 0
	b := max(bs)
}

# Legacy KeyPairGeneratorSpec generates RSA unless the chain sets another type.
_rsa_builder(lines, b, i, _) if {
	contains(lines[b], "KeyPairGeneratorSpec.Builder")
	chain := concat("\n", array.slice(lines, b, i + 8))
	not regex.match(`setKeyType\s*\(\s*(?:"(?i:EC)"|KeyProperties\.KEY_ALGORITHM_EC)|ECGenParameterSpec`, chain)
}

# KeyGenParameterSpec carries no algorithm: the nearest generator decides.
_rsa_builder(lines, b, i, content) if {
	contains(lines[b], "KeyGenParameterSpec.Builder")
	lo := max([0, b - 15])
	hi := min([count(lines) - 1, i + 15])
	gens := [[d, k] |
		some k in numbers.range(lo, hi)
		regex.match(`\b(KeyPairGenerator|KeyGenerator)\s*\.\s*getInstance\s*\(`, lines[k])
		not helpers.is_comment_line(lines[k])
		d := abs(k - b)
	]
	count(gens) > 0
	nearest := min(gens)
	_weak_alg(_kpg_alg_expr(lines[nearest[1]]), content)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

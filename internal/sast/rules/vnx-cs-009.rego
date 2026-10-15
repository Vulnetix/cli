package vulnetix.rules.vnx_cs_009

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-009",
	"name": "C# use of weak cryptographic algorithm (MD5, SHA-1, DES, 3DES, RC2, RC4)",
	"description": "C# code creates or invokes a broken or deprecated cryptographic primitive: MD5 or SHA-1 through MD5/SHA1.Create(), .HashData(), .HashDataAsync() or .TryHashData() (also split across two lines, fully qualified, or through a using alias), the MD5CryptoServiceProvider/MD5Cng/SHA1Managed/SHA1CryptoServiceProvider/SHA1Cng classes, IncrementalHash.CreateHash or CryptographicOperations.HashData with HashAlgorithmName.MD5/SHA1, or an RSA/ECDSA SignData/SignHash/VerifyData/VerifyHash call or CertificateRequest using SHA-1 or MD5 (the HashAlgorithmName inline, on its own line of a multi-line call, or through a variable or field the file assigns from HashAlgorithmName.SHA1/MD5), and the .NET Framework SignData/VerifyData/SignHash/VerifyHash overloads naming \"SHA1\" or \"MD5\" as a string; DES, 3DES or RC2 through DES/TripleDES/RC2.Create() or their CryptoServiceProvider/Cng classes; the algorithm requested by name (HashAlgorithm.Create(\"MD5\"), SymmetricAlgorithm.Create(\"DES\"), CryptoConfig.CreateFromName/MapNameToOID, formatter.SetHashAlgorithm(\"SHA1\")); an XML signature whose SignatureMethod or DigestMethod is set to an RSA/DSA-SHA1 or SHA-1 URL; PBKDF1 through PasswordDeriveBytes; and BouncyCastle MD5Digest/MD4Digest/MD2Digest/Sha1Digest, DesEngine/DesEdeEngine/RC2Engine/RC4Engine and DigestUtilities/CipherUtilities/SignerUtilities lookups of those algorithms. Not reported: HMAC constructions (HMACSHA1, HMACMD5, IncrementalHash.CreateHMAC, used by TOTP and other protocols that do not need collision resistance), RSA-OAEP with SHA-1, PBKDF2 (Rfc2898DeriveBytes), a HashAlgorithmName compared rather than used, an algorithm named only as an enum, property or string, a hash whose surrounding code shows a protocol-fixed non-security use (WebSocket accept key, Gravatar, ETag, Content-MD5, name-based GUID), code under an explicit CA5350/CA5351/CA5373 suppression, comments, string literals and test projects.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-009/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [327],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1600"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["weak-crypto", "cryptography", "csharp"],
}

# Cheap whole-file and per-line gate: every reported shape names one of these
# (algorithm names passed as strings are matched case-insensitively).
_gate_re := `MD[245]|SHA-?1|Sha1Digest|DES|Des(?:Ede)?Engine|RC[24]|PasswordDeriveBytes|XmlDsigDSAUrl|(?i:"(?:md[245]|sha|des|3des|tripledes|triple des|rc[24]|arc4|arcfour))`

# Concrete classes reported when constructed (new X(), new X { }, X x = new()).
_ctor_classes := {
	"MD5CryptoServiceProvider": "MD5",
	"MD5Cng": "MD5",
	"MD5Managed": "MD5",
	"SHA1Managed": "SHA-1",
	"SHA1CryptoServiceProvider": "SHA-1",
	"SHA1Cng": "SHA-1",
	"DESCryptoServiceProvider": "DES",
	"TripleDESCryptoServiceProvider": "3DES",
	"TripleDESCng": "3DES",
	"RC2CryptoServiceProvider": "RC2",
	"PasswordDeriveBytes": "PBKDF1 (PasswordDeriveBytes)",
	"MD5Digest": "MD5",
	"MD4Digest": "MD4",
	"MD2Digest": "MD2",
	"Sha1Digest": "SHA-1",
	"DesEngine": "DES",
	"DesEdeEngine": "3DES",
	"RC2Engine": "RC2",
	"RC4Engine": "RC4",
}

# Abstract algorithm classes reported through their static factories.
_static_classes := {
	"MD5": "MD5",
	"SHA1": "SHA-1",
	"DES": "DES",
	"TripleDES": "3DES",
	"RC2": "RC2",
}

_ctor_alt := concat("|", [k | some k, _ in _ctor_classes])

_static_alt := concat("|", [k | some k, _ in _static_classes])

_factory := `(?:Create|HashData|HashDataAsync|TryHashData)`

_ctor_re := concat("", [`\bnew\s+(?:global::)?(?:[A-Za-z_]\w*\.)*(`, _ctor_alt, `)\s*(?:[\(\{]|$)`])

_typed_new_re := concat("", [`\b(`, _ctor_alt, `)\s+[A-Za-z_]\w*\s*=\s*new\s*\(`])

_static_re := concat("", [`\b(`, _static_alt, `)\s*\.\s*`, _factory, `\s*\(`])

_static_tail_re := concat("", [`\b(`, _static_alt, `)\s*$`])

_static_head_re := concat("", [`^\s*\.\s*`, _factory, `\s*\(`])

# APIs that take the algorithm as a string name.
_named_call := `(?:\bHashAlgorithm\.Create|\bSymmetricAlgorithm\.Create|\bCryptoConfig\.CreateFromName|\bCryptoConfig\.MapNameToOID|\bDigestUtilities\.(?:GetDigest|CalculateDigest)|\bCipherUtilities\.GetCipher|\bSignerUtilities\.GetSigner|\.SetHashAlgorithm)`

_named_code_re := concat("", [_named_call, `\s*\(\s*""`])

_named_raw_re := concat("", [_named_call, `\s*\(\s*"([^"]*)"`])

_name_table := [
	{"re": `(?i)^(?:System\.Security\.Cryptography\.)?MD5(?:CryptoServiceProvider|Cng)?$`, "label": "MD5"},
	{"re": `(?i)^(?:System\.Security\.Cryptography\.)?(?:SHA|SHA1|SHA-1)(?:CryptoServiceProvider|Managed|Cng)?$`, "label": "SHA-1"},
	{"re": `(?i)^MD4$`, "label": "MD4"},
	{"re": `(?i)^MD2$`, "label": "MD2"},
	{"re": `(?i)^(?:System\.Security\.Cryptography\.)?DES(?:CryptoServiceProvider)?$|^(?i:DES)/`, "label": "DES"},
	{"re": `(?i)^(?:System\.Security\.Cryptography\.)?(?:3DES|TripleDES|Triple DES|DESede)(?:CryptoServiceProvider|Cng)?$|^(?i:DESede|TripleDES|3DES)/`, "label": "3DES"},
	{"re": `(?i)^(?:System\.Security\.Cryptography\.)?RC2(?:CryptoServiceProvider)?$|^(?i:RC2)/`, "label": "RC2"},
	{"re": `(?i)^(?:RC4|ARC4|ARCFOUR)(?:/.*)?$`, "label": "RC4"},
	{"re": `(?i)^MD5with`, "label": "MD5"},
	{"re": `(?i)^SHA-?1with`, "label": "SHA-1"},
]

# HashAlgorithmName.MD5/SHA1 used to hash or sign (not compared, not HMAC, not OAEP).
_han_re := `\bHashAlgorithmName\.(MD5|SHA1)\b`

_han_label("MD5") := "MD5"

_han_label("SHA1") := "SHA-1"

_sign_call_re := `\b(?:SignData|SignHash|VerifyData|VerifyHash|CreateHash|HashData|CertificateRequest)\s*\(`

_xmldsig_re := `\b(?:SignatureMethod|DigestMethod)\s*=\s*SignedXml\.XmlDsig(?:RSASHA1|DSA|SHA1)Url\b`

# The code on a line: string and char literals blanked (a literal nested in an
# interpolation hole first), trailing // comment removed.
_code(line) := c if {
	h := regex.replace(line, `\{\s*"(?:[^"\\]|\\.)*"\s*\}`, "{}")
	s := regex.replace(h, `'(?:[^'\\]|\\.)'|"(?:[^"\\]|\\.)*"`, `""`)
	c := regex.replace(s, `//.*$`, "")
}

# using Alias = System.Security.Cryptography.MD5;  ->  [alias, class]
_aliases(content) := {[a[1], a[2]] |
	contains(content, "using ")
	some a in regex.find_all_string_submatch_n(
		concat("", [`(?m)^\s*(?:global\s+)?using\s+([A-Za-z_]\w*)\s*=\s*(?:global::)?(?:[A-Za-z_]\w*\.)*(`, _ctor_alt, `|`, _static_alt, `)\s*;`]),
		content, -1,
	)
}

_all_classes := object.union(_ctor_classes, _static_classes)

# Every algorithm the code on line i creates or invokes.
_labels(lines, i, code, raw, aliases, hvars) := ((((((_ctor_labels(code) | _static_labels(lines, i, code)) | _named_labels(code, raw)) | _han_labels(lines, i, code)) | _xmldsig_labels(code)) | _alias_labels(code, aliases)) | _han_var_labels(code, hvars)) | _legacy_sign_labels(code, raw)

_ctor_labels(code) := {_ctor_classes[m[1]] |
	contains(code, "new")
	some re in [_ctor_re, _typed_new_re]
	some m in regex.find_all_string_submatch_n(re, code, -1)
}

_static_labels(lines, i, code) := {_static_classes[m[1]] |
	some m in regex.find_all_string_submatch_n(_static_re, code, -1)
} | _split_labels(lines, i, code)

# SHA1 / MD5 at the end of the line, .HashData( / .Create( on the next code line.
_split_labels(lines, i, code) := {_static_classes[m[1]] |
	some m in regex.find_all_string_submatch_n(_static_tail_re, code, 1)
	j := helpers.next_code_index(lines, i, 2)
	regex.match(_static_head_re, lines[j])
}

_named_labels(code, raw) := {e.label |
	regex.match(_named_code_re, code)
	some m in regex.find_all_string_submatch_n(_named_raw_re, raw, -1)
	some e in _name_table
	regex.match(e.re, m[1])
}

_han_labels(lines, i, code) := {_han_label(m[1]) |
	contains(code, "HashAlgorithmName")
	some m in regex.find_all_string_submatch_n(_han_re, code, -1)
	_sign_context(lines, i, code)
}

# HashAlgorithmName.MD5/SHA1 assigned to a variable or field in the file
# (var alg = HashAlgorithmName.SHA1;) and that name passed as an argument to a
# hash or sign call:  name -> label.
_han_vars(content) := {m[1]: _han_label(m[2]) |
	contains(content, "HashAlgorithmName")
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*=\s*HashAlgorithmName\.(MD5|SHA1)\s*;`, content, -1)
}

# .NET Framework RSACryptoServiceProvider/DSA overloads that take the hash
# algorithm as a string: rsa.SignData(data, "SHA1"), VerifyData(data, "MD5", sig).
_legacy_sign_re := `\.(?:SignData|VerifyData|SignHash|VerifyHash)\s*\([^;]*?,\s*"(?i:(sha-?1|sha|md5))"\s*[,)]`

_legacy_sign_labels(code, raw) := {l |
	regex.match(`\.(?:SignData|VerifyData|SignHash|VerifyHash)\s*\(`, code)
	some m in regex.find_all_string_submatch_n(_legacy_sign_re, raw, -1)
	l := _legacy_sign_label(lower(m[1]))
}

_legacy_sign_label("md5") := "MD5"

_legacy_sign_label(n) := "SHA-1" if n != "md5"

_han_var_labels(code, hvars) := {l |
	count(hvars) > 0
	regex.match(_sign_call_re, code)
	some v, l in hvars
	regex.match(concat("", [`[(,]\s*`, v, `\s*[,)]`]), code)
}

_xmldsig_labels(code) := {"SHA-1" | regex.match(_xmldsig_re, code)}

_alias_labels(code, aliases) := {_all_classes[pair[1]] |
	some pair in aliases
	_alias_used(code, pair[0], pair[1])
}

_alias_used(code, alias, cls) if {
	_static_classes[cls]
	regex.match(concat("", [`\b`, alias, `\s*\.\s*`, _factory, `\s*\(`]), code)
}

_alias_used(code, alias, cls) if {
	_ctor_classes[cls]
	regex.match(concat("", [`\bnew\s+`, alias, `\s*[\(\{]`]), code)
}

_sign_context(_, _, code) if regex.match(_sign_call_re, code)

# The call opened on one of the five lines above and its argument list is
# still open (no statement terminator in between).
_sign_context(lines, i, _) if {
	i > 0
	some k in numbers.range(max([0, i - 5]), i - 1)
	regex.match(_sign_call_re, _code(lines[k]))
	not _terminated_between(lines, k, i)
}

_terminated_between(lines, k, i) if {
	some m in numbers.range(k, i - 1)
	contains(_code(lines[m]), ";")
}

# Protocol-fixed, non-security uses of a hash: the WebSocket accept key
# (RFC 6455), Gravatar, ETags, Content-MD5 and name-based GUIDs.
_purpose_re := `(?i)websocket|gravatar|(?:^|[^a-z])e-?tag(?:[^a-z]|$)|content-?md5|contenthash|\bnew\s+guid\s*\(`

_non_security_use(lines, i, labels) if {
	every l in labels {
		l in {"MD5", "SHA-1"}
	}
	regex.match(_purpose_re, helpers.code_window(lines, i, 5, 5))
}

# An explicit analyzer suppression: a #pragma warning disable of the weak-crypto
# analyzers above the line and not restored before it, or a SuppressMessage
# attribute on the member.
_suppress_re := `CA535[01]|CA5373`

_suppressed(lines, i) if {
	i > 0
	some k in numbers.range(max([0, i - 200]), i - 1)
	regex.match(`^\s*#\s*pragma\s+warning\s+disable\b`, lines[k])
	regex.match(_suppress_re, lines[k])
	not _restored_between(lines, k, i)
}

_suppressed(lines, i) if {
	i > 0
	some k in numbers.range(max([0, i - 12]), i - 1)
	contains(lines[k], "SuppressMessage")
	regex.match(_suppress_re, lines[k])
}

_restored_between(lines, k, i) if {
	some m in numbers.range(k + 1, i - 1)
	regex.match(`^\s*#\s*pragma\s+warning\s+restore\b`, lines[m])
	regex.match(_suppress_re, lines[m])
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)[\w.]*\.(?:Unit|Integration|Functional|Acceptance|E2E)?Tests?/`, path)

_is_test(path) if regex.match(`(^|/)(?:Unit|Integration|Functional)Tests?/`, path)

_is_test(path) if regex.match(`(^|/|[a-z0-9])Tests?\.cs$`, path)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	regex.match(_gate_re, content)
	not _is_test(path)
	aliases := _aliases(content)
	hvars := _han_vars(content)
	lines := split(content, "\n")
	some i, line in lines
	_line_gate(line, aliases, hvars)
	not helpers.is_comment_line(line)
	code := _code(line)
	labels := _labels(lines, i, code, line, aliases, hvars)
	count(labels) > 0
	not _non_security_use(lines, i, labels)
	not _suppressed(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Weak cryptographic algorithm %s: broken or deprecated for security use. Hash with SHA-256 or stronger (PBKDF2-SHA256, bcrypt or Argon2 for passwords), sign with SHA-256 or stronger, and encrypt with AES-GCM", [concat(", ", sort(labels))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_line_gate(line, _, _) if regex.match(_gate_re, line)

_line_gate(line, aliases, _) if {
	some pair in aliases
	contains(line, pair[0])
}

_line_gate(line, _, hvars) if {
	some v, _ in hvars
	contains(line, v)
}

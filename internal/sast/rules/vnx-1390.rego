# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1390

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1390",
	"name": "Weak Authentication: HTTP Digest or NTLM authentication scheme",
	"description": "CWE-1390 (Weak Authentication) is a class; the concrete form a line-oriented rule can see is code that selects a weak HTTP authentication scheme. HTTP Digest derives its response from MD5 over the password and NTLM from an unsalted MD4 hash, so a captured exchange can be cracked offline or, for NTLM, relayed and replayed (pass-the-hash). Reported: Python requests HTTPDigestAuth(...), requests_ntlm HttpNtlmAuth(...), httpx.DigestAuth(...), urllib HTTPDigestAuthHandler/ProxyDigestAuthHandler(...), Flask-HTTPAuth HTTPDigestAuth() on a server, and a call through a name imported with from requests.auth/requests_ntlm/httpx import ... as X; JavaScript/TypeScript new DigestStrategy(...) (passport-http), passport.authenticate('digest'), httpntlm.get/post/...(), new DigestFetch(...), axios-ntlm NtlmClient(...), and new X(...) where X = require('digest-fetch') or import X from 'digest-fetch'; Java/Kotlin NTCredentials(...), DigestScheme/NTLMScheme(...) and Spring Security DigestAuthenticationFilter/DigestAuthenticationEntryPoint(...) constructed with new (Java) or by a bare call (Kotlin), and AuthSchemes/StandardAuthScheme.NTLM or .DIGEST; C# AuthenticationSchemes.Ntlm/.Digest and CredentialCache.Add(uri, \"NTLM\"|\"Digest\", cred), also with the scheme on its own line of a multi-line Add call; Go ntlmssp.Negotiator{...} and github.com/icholy/digest &digest.Transport{...}. Not reported: opencontainers go-digest (digest.Digest, digest.FromBytes), MessageDigest/DigestInputStream, Basic, Bearer and Negotiate/Kerberos, imports alone, class and function definitions of these names, doctest lines, names that only contain the words (MyDigestStrategyConfig, .digest('hex')), comments, strings and test code. Basic credentials sent over cleartext http:// are VNX-523; plaintext password comparison is VNX-309.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1390/",
	"languages": ["python", "node", "java", "kotlin", "csharp", "go"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1390],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["weak-authentication", "ntlm", "digest-auth", "cwe-1390"],
}

_lang("python", path) if endswith(path, ".py")

_lang("node", path) if regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx)$`, path)

_lang("java", path) if regex.match(`\.(?:java|kt|kts)$`, path)

_lang("csharp", path) if endswith(path, ".cs")

_lang("go", path) if endswith(path, ".go")

_gate := {
	"python": `(?i)digest|ntlm`,
	"node": `(?i)digest|ntlm`,
	"java": `NTCredentials|NTLM|DIGEST|Digest`,
	"csharp": `Ntlm|NTLM|Digest`,
	"go": `ntlmssp\.|"github\.com/icholy/digest"`,
}

_sink := {
	"python": `(?:\b(?:HTTPDigestAuth|HttpNtlmAuth|HTTPDigestAuthHandler|ProxyDigestAuthHandler)|\bhttpx\.DigestAuth)\s*\(`,
	"node": `\bnew\s+(?:DigestStrategy|DigestFetch)\s*\(|\bhttpntlm\.(?:get|post|put|patch|delete|head|options|method)\s*\(|\bNtlmClient\s*\(|\bauthenticate\(\s*['"]digest['"]`,
	"java": `(?:\bnew\s+|[=(,]\s*|\breturn\s+)(?:NTCredentials|DigestScheme|NTLMScheme|DigestAuthenticationFilter|DigestAuthenticationEntryPoint)\s*\(|\b(?:AuthSchemes|StandardAuthScheme)\.(?:NTLM|DIGEST)\b`,
	"csharp": `\bAuthenticationSchemes\.(?:Ntlm|Digest)\b|\.Add\([^;]*,\s*"(?:NTLM|Digest)"\s*,`,
	"go": `\bntlmssp\.Negotiator\s*\{|\bdigest\.Transport\s*\{`,
}

# Declarations, imports and doctest lines name the API without selecting it.
_not_use(line) if regex.match(`^\s*(?:(?:class|def|function|import|from|using|package)\b|>>>|\.\.\.\s)`, line)

_not_use(line) if helpers.is_comment_line(line)

# The API name inside a string literal is prose, not a call (the C# "NTLM"
# argument is matched before strings are stripped, so only the call text matters).
_str_re := `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`

_in_code(lang, line) if {
	lang != "csharp"
	lang != "node"
	regex.match(_sink[lang], regex.replace(line, _str_re, `""`))
}

_in_code("csharp", line) if {
	regex.match(_sink.csharp, line)
	stripped := regex.replace(line, `"(?:NTLM|Digest)"`, "SCHEME")
	regex.match(`\bAuthenticationSchemes\.(?:Ntlm|Digest)\b|\.Add\([^;]*,\s*SCHEME\s*,`, regex.replace(stripped, _str_re, `""`))
}

_in_code("node", line) if {
	regex.match(_sink.node, line)
	stripped := regex.replace(line, `authenticate\(\s*['"]digest['"]`, "authenticate(DIGEST")
	regex.match(`\bnew\s+(?:DigestStrategy|DigestFetch)\s*\(|\bhttpntlm\.\w+\s*\(|\bNtlmClient\s*\(|authenticate\(DIGEST`, regex.replace(stripped, _str_re, `""`))
}

findings contains finding if {
	some path, content in input.file_contents
	some lang, _ in _sink
	_lang(lang, path)
	not helpers.is_test_path(path)
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink[lang], line)
	not _not_use(line)
	_in_code(lang, line)
	not _foreign_digest(lang, content, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Weak HTTP authentication scheme (Digest/NTLM): the exchange is derived from MD5/MD4 of the password and can be cracked offline or relayed. Use a token scheme (OAuth 2.0 / Bearer), mutual TLS, or Kerberos (Negotiate) over TLS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# digest.Transport is only HTTP Digest when it is github.com/icholy/digest
# (opencontainers/go-digest also exports a package named digest).
_foreign_digest("go", content, line) if {
	not regex.match(`\bntlmssp\.Negotiator\s*\{`, line)
	not contains(content, `"github.com/icholy/digest"`)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Weak HTTP authentication scheme (Digest/NTLM): the exchange is derived from MD5/MD4 of the password and can be cracked offline or relayed. Use a token scheme (OAuth 2.0 / Bearer), mutual TLS, or Kerberos (Negotiate) over TLS",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── Aliased imports: from requests.auth import HTTPDigestAuth as DA; DA(u, p)
#    const DigestClient = require('digest-fetch'); new DigestClient(u, p)

_alias_re := {
	"python": `(?m)^\s*from\s+(?:requests\.auth|requests_ntlm|httpx)\s+import\s+(?:HTTPDigestAuth|HttpNtlmAuth|DigestAuth)\s+as\s+(\w+)`,
	"node": `(?m)(?:\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"](?:digest-fetch|httpntlm)['"]\s*\)|^\s*import\s+(\w+)\s+from\s+['"]digest-fetch['"])`,
}

findings contains f if {
	some path, content in input.file_contents
	some lang in {"python", "node"}
	_lang(lang, path)
	not helpers.is_test_path(path)
	regex.match(_gate[lang], content)
	some m in regex.find_all_string_submatch_n(_alias_re[lang], content, 4)
	some k in numbers.range(1, count(m) - 1)
	alias := m[k]
	alias != ""
	not alias in {"HTTPDigestAuth", "HttpNtlmAuth", "DigestFetch", "httpntlm"}
	call_re := _alias_call(lang, alias)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, alias)
	not _not_use(line)
	regex.match(call_re, regex.replace(line, _str_re, `""`))
	f := _finding(path, i, line)
}

_alias_call("python", alias) := concat("", [`(?:^|[^\w.])`, alias, `\s*\(`])

_alias_call("node", alias) := concat("", [`\bnew\s+`, alias, `\s*\(|(?:^|[^\w.])`, alias, `\.(?:get|post|put|patch|delete|head|options|method)\s*\(`])

# ── C#: CredentialCache.Add with the scheme argument on its own line ────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	not helpers.is_test_path(path)
	contains(content, "CredentialCache")
	regex.match(`(?m)^\s*"(?:NTLM|Digest)"\s*,`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`^\s*"(?:NTLM|Digest)"\s*,`, line)
	i > 0
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`\.Add\(\s*(?:$|[^;)]*,\s*$)|\.Add\(\s*$`, lines[j])
	f := _finding(path, i, line)
}

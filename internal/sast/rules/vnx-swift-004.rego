package vulnetix.rules.vnx_swift_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-SWIFT-004",
	"name": "Swift TLS certificate validation disabled in URLSession or AlamoFire",
	"description": "Reports Swift code that accepts a server certificate without validating it: a URLCredential(trust:) built in a function that never evaluates or pins the trust before it (no SecTrustEvaluate/SecTrustEvaluateWithError, evaluator.evaluate(...), certificate or public-key comparison, or a call to a validate/verify/check/pin/evaluate helper above it), which is how a URLSession or NSURLConnection auth-challenge delegate trusts every certificate; an Alamofire DisabledTrustEvaluator()/DisabledEvaluator() or ServerTrustPolicy .disableEvaluation; kCFStreamSSLValidatesCertificateChain set to false; NSURLRequest.setAllowsAnyHTTPSCertificate; a Starscream WebSocket with disableSSLCertValidation = true or FoundationSecurity(allowSelfSigned: true); and a Network.framework sec_protocol_options_set_verify_block whose block completes with true without evaluating the trust. Not reported: URLCredential(trust:) after the trust was evaluated or pinned, URLCredential(user:password:) for HTTP authentication, .performDefaultHandling, pinned or default Alamofire evaluators, the class declarations themselves, string literals, comment lines and test files (where disabling evaluation against a test host is routine). A host-name comparison is not treated as validation, nor is a bare SecTrustEvaluateWithError(trust, nil) statement whose result is discarded. URLCredential( with trust: on the next line is read as one call.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-swift-004/",
	"languages": ["swift"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["tls", "certificate-validation", "swift", "ios"],
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)[^/]*Tests?/`, path)

_is_test(path) if regex.match(`Tests?\.swift$`, path)

_strip(l) := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)

_gate_re := `URLCredential\(\s*(?:trust:|$)|DisabledTrustEvaluator|DisabledEvaluator|disableEvaluation|kCFStreamSSLValidatesCertificateChain|setAllowsAnyHTTPSCertificate|sec_protocol_options_set_verify_block|disableSSLCertValidation|allowSelfSigned`

# evidence that the trust was evaluated or pinned before the credential
_guard_re := `SecTrustEvaluate|\.evaluate\s*\(|SecCertificateCopyData|SecTrustCopyKey|SecTrustCopyPublicKey|SecKeyCopyExternalRepresentation|SecTrustSetAnchorCertificates|\b(?:\w*[a-z0-9_])?(?:Pin|Validat|Verif|Check|IsTrusted|Evaluat)\w*\s*\(|\b(?:pin|validat|verif|check|isTrusted|evaluat)\w*\s*\(|(?i:\w*(?:cert|certificate|key|hash|fingerprint|digest)\w*\s*[!=]=|[!=]=\s*\w*(?:cert|certificate|key|hash|fingerprint|digest))`

_func_start(lines, i) := max(array.concat([max([0, i - 60])], [j |
	some j in numbers.range(max([0, i - 60]), i)
	regex.match(`(^|\s)func\s`, lines[j])
]))

_evaluated(lines, i) if {
	fs := _func_start(lines, i)
	some j in numbers.range(fs, i)
	not helpers.is_comment_line(lines[j])
	regex.match(_guard_re, _strip(lines[j]))
	not regex.match(`^\s*(?:_\s*=\s*)?SecTrustEvaluateWithError\s*\([^,]+,\s*nil\s*\)\s*;?\s*$`, lines[j])
}

_msg := {
	"trust": "URLCredential(trust:) accepts the server certificate without evaluating it; call SecTrustEvaluateWithError (or pin the certificate) first, or use .performDefaultHandling",
	"alamofire": "Alamofire trust evaluation is disabled for this host, so any certificate is accepted; use DefaultTrustEvaluator or a pinned evaluator",
	"stream": "kCFStreamSSLValidatesCertificateChain is set to false, disabling certificate-chain validation on the stream",
	"anycert": "setAllowsAnyHTTPSCertificate accepts any certificate for the host",
	"starscream": "The Starscream WebSocket accepts any (or self-signed) certificate; keep certificate validation on and pin with FoundationSecurity(allowSelfSigned: false) or a certPinner",
	"verify": "The TLS verify block completes with true without evaluating the trust; call SecTrustEvaluateWithError on sec_trust_copy_ref(trust) and complete with its result",
}

_bypass(_, _, s, "trust") if {
	regex.match(`URLCredential\(\s*trust:`, s)
}

# URLCredential(
#     trust: serverTrust)
_bypass(lines, i, s, "trust") if {
	regex.match(`URLCredential\(\s*$`, s)
	i + 1 < count(lines)
	regex.match(`^\s*trust:`, lines[i + 1])
}

_bypass(_, _, s, "starscream") if {
	regex.match(`\.disableSSLCertValidation\s*=\s*true\b|\bFoundationSecurity\(\s*allowSelfSigned:\s*true\b`, s)
}

_bypass(_, _, s, "alamofire") if {
	regex.match(`\b(?:DisabledTrustEvaluator|DisabledEvaluator)\s*\(|\.disableEvaluation\b`, s)
}

_bypass(lines, i, s, "stream") if {
	contains(s, "kCFStreamSSLValidatesCertificateChain")
	txt := concat(" ", array.slice(lines, i, min([count(lines), i + 2])))
	regex.match(`kCFStreamSSLValidatesCertificateChain[^\n]*?(?::|=|,)\s*(?:false|kCFBooleanFalse|NSNumber\(value:\s*false\)|0\b)`, txt)
}

_bypass(_, _, s, "anycert") if {
	regex.match(`setAllowsAnyHTTPSCertificate\s*\(\s*true`, s)
}

_bypass(lines, i, s, "verify") if {
	contains(s, "sec_protocol_options_set_verify_block")
	body := [l | some l in array.slice(lines, i, min([count(lines), i + 6])); not helpers.is_comment_line(l)]
	txt := concat("\n", body)
	regex.match(`\b\w+\(\s*true\s*\)`, txt)
	not regex.match(`SecTrustEvaluate|\.evaluate\s*\(`, txt)
}

_ok(lines, i, _, "trust") if _evaluated(lines, i)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".swift")
	not _is_test(path)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate_re, line)
	not helpers.is_comment_line(line)
	s := _strip(line)
	some kind, msg in _msg
	_bypass(lines, i, s, kind)
	not _ok(lines, i, s, kind)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

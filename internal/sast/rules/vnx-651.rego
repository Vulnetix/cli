# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_651

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-651",
	"name": "Exposure of WSDL File Containing Sensitive Information",
	"description": "A published WSDL contract that tells every client something it should not. Reported in .wsdl and .xsd files: an element or attribute whose name ends in a credential word (password, passwd, secret, apiKey, token, privateKey: adminPassword, client_secret) given a non-empty default= or fixed= value that is not a number, a boolean or a scheme name such as Bearer, a soap/soap12/http:address location carrying user:password@ credentials, and an operation named like a debug or internal back door (debug*, internal*, dump*, backdoor*, hidden*, exec/execute/run + Command/Cmd/Shell/Sql/Script/Query, get*Password/Secret/PrivateKey/Credentials). Reported in code, because each one is generated into the service's WSDL: a JAX-WS @WebMethod (Java), a spyne @rpc/@srpc (Python) or a WCF [OperationContract] (C#) on a method with such a name. Not reported: ordinary business operations (changePassword, getPasswordPolicy, testConnection, executeOrder), credential elements without a value or with an empty one, settings that only describe a credential (tokenType, passwordMinLength, tokenExpirySeconds), https or credential-free addresses, @WebMethod(exclude = true), methods without the service annotation, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-651/",
	"languages": ["java", "python", "csharp", "xml"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [651],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["wsdl", "soap", "information-exposure", "cwe-651"],
}

# The name ends in the credential word: tokenType, passwordMinLength and
# secretQuestionEnabled describe a credential, they do not hold one.
_cred_name := `(?i)name\s*=\s*"[\w:.-]*(?:password|passwd|pwd|secret|api_?key|apikey|token|private_?key)"`

# A non-empty value that is not a boolean or a number.
_cred_value := `\b(?:default|fixed)\s*=\s*"(?:[^"]*[^"\d.\s-][^"]*)"`

_trivial_value := `\b(?:default|fixed)\s*=\s*"(?i:true|false|none|null|bearer|basic)"`

_addr_creds := `<(?:soap|soap12|http|wsdl):address\s+location\s*=\s*"[a-z]+://[^/"@\s:]+:[^/"@\s]+@`

_op_line := `<(?:wsdl:)?operation\s+name\s*=\s*"([A-Za-z_]\w*)"`

# Operation names that announce a debug, internal or administrative back door,
# or a secret being handed out.
_sensitive_op := `(?i)^(?:debug|internal|dump|backdoor|hidden)|^(?:exec|execute|run)_?(?:command|cmd|shell|sql|script|query)|^get_?\w*(?:password|secret|private_?key|credentials?)$`

_is_wsdl(path) if endswith(lower(path), ".wsdl")

_is_wsdl(path) if endswith(lower(path), ".xsd")

_msg := "WSDL exposes sensitive information (a credential value, a credentialed address or a debug/internal operation) to every client that fetches the contract"

findings contains finding if {
	some path, content in input.file_contents
	_is_wsdl(path)
	regex.match(`(?i)password|passwd|pwd|secret|api_?key|token|private_?key|address|operation`, content)
	lines := split(content, "\n")
	some i, line in lines
	not regex.match(`^\s*<!--`, line)
	_wsdl_hit(line)
	finding := _finding(path, i, line)
}

_wsdl_hit(line) if {
	regex.match(_cred_name, line)
	regex.match(_cred_value, line)
	not regex.match(_trivial_value, line)
}

_wsdl_hit(line) if regex.match(_addr_creds, line)

_wsdl_hit(line) if {
	m := regex.find_all_string_submatch_n(_op_line, line, 1)
	count(m) > 0
	regex.match(_sensitive_op, m[0][1])
}

# Java JAX-WS @WebMethod / Python spyne @rpc / C# WCF [OperationContract]
_annot(path) := `^\s*@WebMethod\b` if endswith(path, ".java")

_annot(path) := `^\s*@s?rpc\b` if endswith(path, ".py")

_annot(path) := `^\s*\[\s*OperationContract\b` if endswith(path, ".cs")

_annot_gate(path) := "@WebMethod" if endswith(path, ".java")

_annot_gate(path) := "rpc" if endswith(path, ".py")

_annot_gate(path) := "OperationContract" if endswith(path, ".cs")

# The method name on a declaration line: the identifier before `(`.
_method_name(path, line) := n if {
	endswith(path, ".py")
	m := regex.find_all_string_submatch_n(`^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`, line, 1)
	count(m) > 0
	n := m[0][1]
}

_method_name(path, line) := n if {
	not endswith(path, ".py")
	not regex.match(`^\s*[@\[]`, line)
	m := regex.find_all_string_submatch_n(`(?:^|\s)([A-Za-z_]\w*)\s*\(`, line, 1)
	count(m) > 0
	n := m[0][1]
	not n in {"if", "for", "while", "switch", "return", "new", "catch"}
}

findings contains finding if {
	some path, content in input.file_contents
	pat := _annot(path)
	contains(content, _annot_gate(path))
	lines := split(content, "\n")
	some a, aline in lines
	regex.match(pat, aline)
	not regex.match(`exclude\s*=\s*true`, aline)
	some j in numbers.range(a + 1, min([count(lines) - 1, a + 4]))
	not helpers.is_comment_line(lines[j])
	name := _method_name(path, lines[j])
	_first_decl(path, lines, a, j)
	regex.match(_sensitive_op, name)
	finding := _finding(path, j, lines[j])
}

# j is the first method-declaration line after the annotation at a.
_first_decl(path, lines, a, j) if {
	not _earlier_decl(path, lines, a, j)
}

_earlier_decl(path, lines, a, j) if {
	a + 1 <= j - 1
	some k in helpers.span(a + 1, j - 1)
	not helpers.is_comment_line(lines[k])
	_method_name(path, lines[k])
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

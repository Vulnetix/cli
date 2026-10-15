# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_397

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-397",
	"name": "Declaration of Throws for Generic Exception",
	"description": "A Java method or interface method declares throws Exception or throws Throwable (alone, java.lang.-qualified or inside a list such as throws IOException, Exception), on the signature line or on a throws continuation line of a multi-line signature. Callers cannot tell which failures to handle and are forced to catch the generic type themselves. Not reported: a throws list of specific types (including names that merely start with Exception, such as ExceptionInInitializerError), a Spring Security configuration method taking HttpSecurity, WebSecurity, AuthenticationManagerBuilder or AuthenticationConfiguration (whose builders themselves throw Exception), sample, example and demo directories, a file declaring a @FunctionalInterface (a throwing functional interface, like Callable, must declare the generic type), a method annotated @Override (its signature is dictated by the supertype: AutoCloseable.close, HandlerInterceptor.preHandle), main(String[]), Callable.call(), AutoCloseable.close() and InitializingBean.afterPropertiesSet() implementations, test files, comments, Javadoc and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-397/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [397],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["error-handling", "cwe-397"],
}

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_throws_re := `(?:\)\s*|^\s*)throws\s+(?:[\w.]+\s*,\s*)*(?:java\.lang\.)?(?:Exception|Throwable)\s*(?:[,{;]|$)`

# Interface methods whose signature is dictated by the JDK or Spring.
_dictated_re := `\b(?:void\s+main\s*\(\s*(?:final\s+)?String\s*(?:\[\]\s*\w+|\.\.\.\s*\w+|\w+\s*\[\])|\w+\s+call\s*\(\s*\)|\b(?:HttpSecurity|WebSecurity|AuthenticationManagerBuilder|AuthenticationConfiguration)\s+\w+|void\s+close\s*\(\s*\)|void\s+afterPropertiesSet\s*\(\s*\))`

# The declaration's first line: the line at or above i that opens the
# parameter list (contains '(' ), within 8 lines.
_decl_start(lines, i) := s if {
	cands := [j |
		some j in numbers.range(max([0, i - 8]), i)
		contains(lines[j], "(")
		not helpers.is_comment_line(lines[j])
	]
	count(cands) > 0
	s := cands[count(cands) - 1]
}

_overrides(lines, s) if {
	some j in numbers.range(max([0, s - 12]), s)
	regex.match(`^\s*@Override\b`, lines[j])
	not _statement_between(lines, j, s)
}

_statement_between(lines, j, s) if {
	some k in numbers.range(j + 1, s)
	k > j
	k < s
	regex.match(`[;{}]\s*$`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "throws")
	regex.match(`throws[^;{]*\b(?:Exception|Throwable)\s*[,{;\n]`, content)
	not helpers.is_test_path(path)
	not regex.match(`(?:^|/)(?:samples?|examples?|demos?)/`, path)

	# a throwing functional interface (like Callable) must declare the
	# generic type to be usable with any lambda
	not regex.match(`(?m)^\s*@(?:java\.lang\.)?FunctionalInterface\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "throws")
	not helpers.is_comment_line(line)
	regex.match(_throws_re, _strip_strings(line))
	s := _decl_start(lines, i)
	sig := concat(" ", array.slice(lines, s, i + 1))
	not regex.match(_dictated_re, sig)
	not _overrides(lines, s)
	finding := {
		"rule_id": metadata.id,
		"message": "Method declares throws Exception/Throwable: callers cannot tell which failures to expect and must catch the generic type. Declare the specific checked exceptions instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

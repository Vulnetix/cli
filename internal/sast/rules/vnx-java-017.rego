package vulnetix.rules.vnx_java_017

import rego.v1
import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-017",
	"name": "Java HTTP response splitting via unsanitised header value",
	"description": "A value read from the HTTP request reaches HttpServletResponse.setHeader(), addHeader() or sendRedirect() without CR/LF neutralisation, so an attacker who can put \\r\\n into it can inject headers or split the response. Reported: the request read inline in the call (request.getParameter/getParameterValues/getHeader/getHeaders/getQueryString/getPathInfo), a variable assigned from one of those up to 20 lines above, one intermediate assignment or concatenation of such a variable, and Spring handler parameters bound by @RequestParam, @PathVariable, @RequestHeader or @CookieValue; calls broken across lines are read to their semicolon. The header call must be on a response receiver (response, resp, res, httpResponse, getResponse()). Not reported: a value passed through replace/replaceAll, URLEncoder.encode, an OWASP/ESAPI/commons encoder, a sanitize/validate/escape helper, a numeric parse or a matches()/Pattern check on the way; constants and server-side values (getContextPath, getAttribute); outbound HTTP client headers (OkHttp/Apache builders); the pattern in comments and string literals. Flows through fields, collections or other methods are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-017/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [113],
	"capec": ["CAPEC-34"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["injection", "crlf", "http", "java"],
}

_src := `\.\s*(getParameter|getParameterValues|getHeader|getHeaders|getQueryString|getPathInfo)\s*\(`

_file_src := `getParameter|getHeader|getQueryString|getPathInfo|@RequestParam|@PathVariable|@RequestHeader|@CookieValue`

_sink := `((?i:\b\w*resp\w*|\bres)(\(\))?\s*\.\s*(addHeader|setHeader)|\.\s*sendRedirect)\s*\(`

_spring_param := `@(?:RequestParam|PathVariable|RequestHeader|CookieValue)\b(?:\s*\([^)]*\))?\s+(?:final\s+)?(?:String|Optional<String>|String\[\]|List<String>)\s+(\w+)`

_sanitiser := `\.\s*replace(All|First)?\s*\(|URLEncoder\.encode|Encode\.for|ESAPI\.|StringEscapeUtils|UriUtils\.encode|(?i:sanitiz|sanitis|validat|escape|strip(crlf|newline)|clean)|\b(Integer|Long|Short)\.(parseInt|parseLong|parseShort|valueOf)\s*\(|UUID\.fromString|\.\s*matches\s*\(|Pattern\.|\.\s*matcher\s*\(|isValid|allowed|whitelist|allowlist`

_strip(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`)

# The sink statement: line i and the lines after it up to the first `;`.
_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 4])
	ends := [k | some k in numbers.range(i, end); contains(lines[k], ";")]
	last := _first_or(ends, end)
	s := _strip(concat(" ", [lines[k] | some k in numbers.range(i, last)]))
}

_first_or(arr, d) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_sanitised_near(lines, i, v) if {
	some j in numbers.range(max([0, i - 20]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\b`, v, `\b`]), l)
	regex.match(_sanitiser, l)
}

_spring_names(lines, i) := {v |
	some j in numbers.range(max([0, i - 40]), i)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(_spring_param, lines[j], -1)
	v := m[1]
}

_direct(lines, i) := helpers.tainted_names(lines, i, 20, _src) | _spring_names(lines, i)

_tainted(lines, i) := t1 | t2 if {
	t1 := _direct(lines, i)
	t2 := {w |
		some j in numbers.range(max([0, i - 20]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		some v in t1
		regex.match(concat("", [`\b`, v, `\b`]), _strip(l))
		w := helpers.assigned_first(l)
		w != v
		not regex.match(_sanitiser, l)
	}
}

_reaches(lines, i, stmt) if regex.match(_src, stmt)

_reaches(lines, i, stmt) if {
	some v in _tainted(lines, i)
	regex.match(concat("", [`\b`, v, `\b`]), stmt)
	not _sanitised_near(lines, i, v)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`Header\s*\(|sendRedirect`, content)
	regex.match(_file_src, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Header|sendRedirect`, line)
	not helpers.is_comment_line(line)
	regex.match(_sink, _strip(line))
	stmt := _stmt(lines, i)
	not regex.match(_sanitiser, stmt)
	_reaches(lines, i, stmt)
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP response header or redirect built from request input without CR/LF neutralisation; strip \\r and \\n (or encode the value) before setHeader()/addHeader()/sendRedirect() to prevent response splitting",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

package vulnetix.rules.vnx_java_026

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-026",
	"name": "Java Spring/servlet file serving without access control",
	"description": "A Spring or servlet handler serves a file whose name or path comes from the request, and the handler makes no authorisation decision. Reported: new FileSystemResource/UrlResource/PathResource/FileUrlResource(...) or new InputStreamResource(...) built from a request value, and FileCopyUtils/StreamUtils.copyToByteArray, Files.readAllBytes, Files.copy, IOUtils.copy/toByteArray of such a path returned in the response body or written to the response stream (directly, or through a local that is written, returned or put in a body within the next 8 lines). A request value is a handler parameter bound with @PathVariable, @RequestParam, @RequestHeader or @RequestPart, or a local assigned from getParameter/getHeader/getPathInfo/getQueryString/getRequestURI, followed through up to two local assignments (File, Path.resolve, string concatenation). Not reported: a handler (or its class) carrying @PreAuthorize/@PostAuthorize/@Secured/@RolesAllowed, a handler that consults the caller (Principal, Authentication, @AuthenticationPrincipal, getUserPrincipal, isUserInRole, getRemoteUser, SecurityContextHolder, hasPermission or an owner check), constant paths, ClassPathResource, in-memory streams (ByteArrayInputStream), comments and string literals. Flows through other methods or files are not followed; path canonicalisation alone is not treated as access control.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-026/",
	"languages": ["java"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [552],
	"capec": ["CAPEC-87"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["access-control", "file-exposure", "spring", "java"],
}

_str_re := `"(?:[^"\\\n]|\\.)*"`

_strip(text) := regex.replace(text, _str_re, `""`)

_resource_re := `new\s+(?:FileSystemResource|UrlResource|PathResource|FileUrlResource|InputStreamResource)\s*\(`

_copy_re := `(?:FileCopyUtils\.copyToByteArray|StreamUtils\.copyToByteArray|Files\.readAllBytes|Files\.copy|IOUtils\.copy|IOUtils\.toByteArray)\s*\(`

_file_gate := `(?m)(FileSystemResource|UrlResource|PathResource|FileUrlResource|InputStreamResource|copyToByteArray|Files\.readAllBytes|Files\.copy|IOUtils\.)`

_handler_re := `@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b|\bvoid\s+do(?:Get|Post|Put)\s*\(|\bservice\s*\(\s*HttpServletRequest`

_authz_re := `@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|\bPrincipal\b|\bAuthentication\b|@AuthenticationPrincipal|getUserPrincipal|isUserInRole|getRemoteUser|SecurityContextHolder|hasPermission|(?i:checkAccess|canAccess|isOwner|getOwner|authoriz)`

_source_call_re := `\.(?:getParameter|getHeader|getPathInfo|getQueryString|getRequestURI|getServletPath)\s*\(`

_bound_re := `@(?:PathVariable|RequestParam|RequestHeader|RequestPart)(?:\s*\([^)]*\))?\s+(?:final\s+)?[\w<>\[\].?]+\s+([A-Za-z_]\w*)`

# The handler holding line i: the nearest mapping annotation or servlet
# method within 30 lines above, widened by 3 lines for stacked annotations.
_method_start(lines, i) := s if {
	ks := [k | some k in numbers.range(max([0, i - 30]), i); regex.match(_handler_re, lines[k])]
	count(ks) > 0
	s := max([0, max(ks) - 3])
}

_class_authz(content) if regex.match(`(?m)^@(?:PreAuthorize|Secured|RolesAllowed)\b[^\n]*\n(?:@[^\n]*\n)*(?:public\s+)?(?:final\s+)?class\b`, content)

_authorised(lines, s, i) if {
	some k in numbers.range(s, i)
	not helpers.is_comment_line(lines[k])
	regex.match(_authz_re, _strip(lines[k]))
}

# Name assigned on line k (tolerates a wrapped initialiser: `var f =`).
_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:final\s+)?(?:[\w<>\[\],.?]+\s+)?([A-Za-z_]\w*)\s*=(?:[^=]|$)`, line, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"return", "else"}
}

_rhs(lines, k) := r if {
	parts := split(_strip(lines[k]), "=")
	r0 := concat("=", array.slice(parts, 1, count(parts)))
	r := concat(" ", [r0, _cont(lines, k)])
}

_cont(lines, k) := _strip(lines[k + 1]) if {
	regex.match(`=\s*$`, lines[k])
	k + 1 < count(lines)
}

_cont(lines, k) := "" if not regex.match(`=\s*$`, lines[k])

_cont(lines, k) := "" if {
	regex.match(`=\s*$`, lines[k])
	k + 1 >= count(lines)
}

_mentions(text, names) if {
	some t in names
	regex.match(concat("", [`\b`, t, `\b`]), text)
}

_sources(lines, s, i) := {v |
	some k in numbers.range(s, i)
	l := lines[k]
	not helpers.is_comment_line(l)
	contains(l, "@")
	some m in regex.find_all_string_submatch_n(_bound_re, l, -1)
	v := m[1]
} | {v |
	some k in numbers.range(s, i)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_source_call_re, l)
	v := _assigned(l)
}

_step(lines, s, i, names) := names | {v |
	some k in numbers.range(s, i - 1)
	l := lines[k]
	contains(l, "=")
	not helpers.is_comment_line(l)
	v := _assigned(l)
	_mentions(_rhs(lines, k), names)
}

_tainted(lines, s, i) := t2 if {
	t0 := _sources(lines, s, i)
	count(t0) > 0
	t1 := _step(lines, s, i, t0)
	t2 := _step(lines, s, i, t1)
}

# The sink's argument text (rest of the line and the next one), literals blanked.
_sink_arg(lines, i, re) := a if {
	m := regex.find_all_string_submatch_n(concat("", [re, `(.*)$`]), _strip(lines[i]), 1)
	count(m) > 0
	nxt := [_strip(lines[k]) | some k in numbers.range(i + 1, min([count(lines) - 1, i + 1])); i + 1 < count(lines)]
	a := concat(" ", array.concat([m[0][1]], nxt))
}

_sinks(lines, i, line) := {arg |
	regex.match(_resource_re, line)
	arg := _sink_arg(lines, i, _resource_re)
	not regex.match(`^\s*new\s+(?:ByteArrayInputStream|StringReader|ByteArrayResource)\b`, arg)
} | {arg |
	regex.match(_copy_re, line)
	regex.match(`\.body\(|\breturn\b|getOutputStream\(|getWriter\(`, line)
	arg := _sink_arg(lines, i, _copy_re)
} | {arg |
	# byte[] data = Files.readAllBytes(p); ... out.write(data) / return data
	regex.match(_copy_re, line)
	not regex.match(`\.body\(|\breturn\b|getOutputStream\(|getWriter\(`, line)
	v := _assigned(line)
	_served_later(lines, i, v)
	arg := _sink_arg(lines, i, _copy_re)
}

_served_later(lines, i, v) if {
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	regex.match(concat("", [`(?:\.write\(|\.body\(|\breturn\b)[^;]*\b`, v, `\b`]), lines[k])
}

_message := "File served from a request-supplied name or path with no authorisation check in the handler; verify the caller may read this file (ownership lookup, @PreAuthorize) and serve it by an opaque id from a confined directory"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_file_gate, content)
	not _class_authz(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_file_gate, line)
	args := _sinks(lines, i, _strip(line))
	count(args) > 0
	s := _method_start(lines, i)
	not _authorised(lines, s, i)
	tainted := _tainted(lines, s, i)
	some arg in args
	_mentions(arg, tainted)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

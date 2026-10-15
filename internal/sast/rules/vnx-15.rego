# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_15

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-15",
	"name": "External Control of System or Configuration Setting",
	"description": "A value read from an HTTP request is written into a process-wide setting: an environment variable (Go os.Setenv/syscall.Setenv, Python os.environ[...] = / os.environ.update / os.putenv, Node process.env.X = / process.env[k] = / Object.assign(process.env, ...), PHP putenv), the module search path (Python sys.path.append/insert, PHP set_include_path), runtime configuration (Go viper.Set*, PHP ini_set/ini_alter, Java System.setProperty/setProperties/Security.setProperty) or the database catalog of a JDBC connection (setCatalog). The request value must be on the setting line or assigned from the request (Go r.FormValue/r.URL.Query()/r.Header.Get/PathValue and gin/echo c.Query/c.Param/c.PostForm, Flask/Django request.args/form/json/values/GET/POST/headers/cookies, Express req.body/query/params/headers/cookies, Java getParameter/getHeader, PHP $_GET/$_POST/$_REQUEST/$_COOKIE) within the 15 lines above (including names destructured from req.body/req.query, and a call whose arguments continue on the next two lines). Not reported: constant values, settings taken from the environment or a config file, reads of the environment beside request data, a request value checked against an allow-list (in/not in, includes, has, indexOf, in_array, contains, an allowed/whitelist name, a regex match) before the write, and the patterns in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-15/",
	"languages": ["go", "java", "node", "php", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [15],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["config", "external-control", "injection", "cwe-15"],
}

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

# Cheap whole-file needles: the file names a setting sink at all.
_sink_needles := {
	"go": {"Setenv(", "viper.Set"},
	"py": {"environ", "putenv(", "sys.path."},
	"js": {"process.env"},
	"java": {"setProperty(", "setProperties(", "setCatalog("},
	"php": {"ini_set(", "ini_alter(", "putenv(", "set_include_path("},
}

# ...and reads a request somewhere.
_source_needles := {
	"go": {"r.", "req.", "request.", "c."},
	"py": {"request."},
	"js": {"req.", "request.", "ctx."},
	"java": {"getParameter", "getHeader"},
	"php": {"$_"},
}

_sink := {
	"go": `\b(os|syscall)\.Setenv\s*\(|\bviper\.Set\w*\s*\(`,
	"py": `\bos\.environ\s*\[[^\]]+\]\s*=[^=]|\bos\.environ\.(update|setdefault)\s*\(|\bos\.putenv\s*\(|\bsys\.path\.(append|insert|extend)\s*\(`,
	"js": `\bprocess\.env\s*(\.\s*\w+|\[[^\]]+\])\s*=[^=]|\bObject\.assign\s*\(\s*process\.env\s*,`,
	"java": `\b(System|Security)\.setPropert(y|ies)\s*\(|\.setCatalog\s*\(`,
	"php": `(^|[^\w>:$])(ini_set|ini_alter|putenv|set_include_path)\s*\(`,
}

_source := {
	"go": `\b(r|req|request)\.(FormValue|PostFormValue|URL\.Query\(\)|Header\.Get|PathValue|Form\.Get|PostForm\.Get)|\bc\.(Query|DefaultQuery|Param|PostForm|DefaultPostForm|FormValue|QueryParam|GetHeader)\s*\(|\bmux\.Vars\s*\(`,
	"py": `\brequest\.(args|form|values|json|get_json|GET|POST|headers|cookies|data|query_params)\b`,
	"js": `\b(req|request)\.(body|query|params|headers|cookies)\b|\bctx\.(query|params|request\.body)\b`,
	"java": `\.(getParameter|getParameterValues|getHeader)\s*\(`,
	"php": `\$_(GET|POST|REQUEST|COOKIE)\b`,
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# String literals are blanked so a sink or a source quoted in a message is not
# code. PHP keeps the request superglobal outside its key, so it still matches.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# The name an assignment gives, as a regex fragment for the sink line.
_assigned(lang, line) := concat("", [`\$`, m[0][1], `\b`]) if {
	lang == "php"
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, line, 1)
	count(m) > 0
}

_assigned(lang, line) := concat("", [`\b`, v, `\b`]) if {
	lang != "php"
	not _destructure(lang, line)
	v := helpers.assigned_first(line)
}

# JavaScript destructuring: const { region, zone: z } = req.body
_destructure(lang, line) := names if {
	lang == "js"
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=[^=]`, line, 1)
	count(m) > 0
	parts := [n |
		some p in split(m[0][1], ",")
		seg := split(p, ":")
		n := trim_space(regex.replace(seg[count(seg) - 1], `=.*$`, ""))
		regex.match(`^\w+$`, n)
	]
	count(parts) > 0
	names := concat("|", parts)
}

_assigned(lang, line) := concat("", [`\b(`, names, `)\b`]) if {
	names := _destructure(lang, line)
}

# The request value is on the setting line itself.
_reaches(lang, _, _, c) if regex.match(_source[lang], c)

# Or a name assigned from the request above reaches it, with no allow-list
# check of that name on the way.
_reaches(lang, lines, i, c) if {
	start := max([0, i - 15])
	some j in numbers.range(start, i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_source[lang], _code(prev))
	re := _assigned(lang, prev)
	regex.match(re, c)
	not _allowlisted(lines, j, i, re)
}

_guard_re := `(?i)\bnot\s+in\b|\bin\s+[\w.]+\s*:|\.includes\s*\(|\bin_array\s*\(|\.contains\s*\(|\.has\s*\(|\.indexOf\s*\(|slices\.Contains|\ballow|whitelist|\bpermitted|\bvalid_|\bis_valid|preg_match\s*\(|\bre\.(full)?match\s*\(|\.matches\s*\(|MatchString\s*\(|\.test\s*\(`

_allowlisted(lines, j, i, re) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	l := lines[k]
	regex.match(re, l)
	regex.match(_guard_re, l)
	not helpers.is_comment_line(l)
}

# A call broken over lines (System.setProperty(\n "k", v)) is read with the
# next two lines, so its arguments are seen.
_opens_more(c) if count(regex.find_all_string_submatch_n(`\(`, c, -1)) > count(regex.find_all_string_submatch_n(`\)`, c, -1))

_with_continuation(lines, i, c) := concat(" ", array.concat([c], [_code(lines[k]) | some k in numbers.range(i + 1, min([i + 2, count(lines) - 1]))])) if {
	_opens_more(c)
	i + 1 < count(lines)
}

_with_continuation(lines, i, c) := c if not _opens_more(c)

_with_continuation(lines, i, c) := c if {
	_opens_more(c)
	i + 1 >= count(lines)
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_any(content, _sink_needles[lang])
	_has_any(content, _source_needles[lang])
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, _sink_needles[lang])
	not helpers.is_comment_line(line)
	c0 := _code(line)
	regex.match(_sink[lang], c0)
	c := _with_continuation(lines, i, c0)
	_reaches(lang, lines, i, c)
	finding := {
		"rule_id": metadata.id,
		"message": "A value from the HTTP request is written into a process-wide setting (environment variable, module search path, runtime configuration or database catalog). A caller can then change how the whole process behaves: proxies, locale, include paths, log levels. Map the request to a fixed set of allowed values instead of passing it through",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

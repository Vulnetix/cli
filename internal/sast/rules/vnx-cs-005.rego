package vulnetix.rules.vnx_cs_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-005",
	"name": "C# MVC action accepting cross-site form posts without anti-forgery validation",
	"description": "An ASP.NET MVC or ASP.NET Core MVC controller action that a cross-site HTML form can reach is not protected against Cross-Site Request Forgery. Reported: the [HttpPost] (including [HttpPost(\"route\")] and [HttpPost, Route(...)]) or [AcceptVerbs(HttpVerbs.Post)] attribute of an action in a class deriving from Controller (directly or through a base controller), when neither the action's own attribute block nor the class carries [ValidateAntiForgeryToken], [AutoValidateAntiforgeryToken] or [IgnoreAntiforgeryToken]; [HttpPut]/[HttpDelete]/[HttpPatch] are reported only where a form can reach them, in ASP.NET MVC 5 (System.Web.Mvc honours X-HTTP-Method-Override) or in a project that calls UseHttpMethodOverride. Not reported: a project-wide anti-forgery filter (Filters.Add of AutoValidateAntiforgeryTokenAttribute or ValidateAntiForgeryTokenAttribute), a base controller declared with the attribute, [ApiController] classes (or [assembly: ApiController]), ControllerBase and Web API 2 ApiController classes, actions restricted to JSON with [Consumes(\"application/json\")] or a [FromBody] parameter (a form cannot send that content type without a CORS preflight), PUT/DELETE/PATCH in ASP.NET Core without method override, test code, and attributes in comments. The CSRF exposure also depends on cookie authentication and SameSite settings, which are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-005/",
	"languages": ["csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [352],
	"capec": ["CAPEC-62"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["csrf", "mvc", "csharp"],
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `//.*$`, "")

# ── The verb attribute ───────────────────────────────────────────────────

_verb(line) := "post" if regex.match(`\[\s*AcceptVerbs\s*\(\s*(?:HttpVerbs\.Post\b|"POST")`, line)

_verb(line) := lower(m[0][1]) if {
	not regex.match(`\[\s*AcceptVerbs\s*\(`, line)
	m := regex.find_all_string_submatch_n(`(?:\[|,)\s*(?:[\w.]*\.)?Http(Post|Put|Delete|Patch)(?:Attribute)?\s*(?:\(|,|\])`, _code(line), 1)
	count(m) > 0
}

# A browser form posts; PUT/DELETE/PATCH need method override to be reachable.
_reachable("post", _)

_reachable(verb, content) if {
	verb != "post"
	contains(content, "System.Web.Mvc")
}

_reachable(verb, _) if {
	verb != "post"
	_method_override
}

_method_override if {
	some p, c in input.file_contents
	endswith(p, ".cs")
	contains(c, "UseHttpMethodOverride")
	some l in split(c, "\n")
	contains(l, "UseHttpMethodOverride")
	not helpers.is_comment_line(l)
}

# ── Mitigations ──────────────────────────────────────────────────────────

_token_re := `\b(ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|IgnoreAntiforgeryToken)(Attribute)?\b`

_json_only_re := `\[\s*Consumes\s*\(|\[\s*FromBody\b`

# A project-wide filter, or [assembly: ApiController].
_project_mitigated if {
	some p, c in input.file_contents
	endswith(p, ".cs")
	_has_any(c, {"AntiforgeryToken", "AntiForgeryToken", "assembly: ApiController", "assembly:ApiController"})
	some l in split(c, "\n")
	not helpers.is_comment_line(l)
	regex.match(`(?i)Filters\s*\.\s*Add\w*\s*(<\s*(Auto)?ValidateAntiforgeryTokenAttribute\s*>|\(\s*(new\s+)?(Auto)?ValidateAntiforgeryTokenAttribute\b|\(\s*typeof\s*\(\s*(Auto)?ValidateAntiforgeryTokenAttribute)|\[\s*assembly\s*:\s*ApiController`, l)
}

_attr_or_skip(l) if regex.match(`^\s*\[`, l)

_attr_or_skip(l) if trim_space(l) == ""

_attr_or_skip(l) if helpers.is_comment_line(l)

# The attribute block of the action: the attribute lines around i, then the
# signature (which may wrap).
_action_block(lines, i) := txt if {
	n := count(lines) - 1
	ups := [j | some j in numbers.range(max([0, i - 8]), i - 1); not _attr_or_skip(lines[j])]
	start := max(array.concat([max([0, i - 8]) - 1], ups)) + 1
	downs := [k | some k in numbers.range(i + 1, min([n, i + 8])); not _attr_or_skip(lines[k])]
	sig := min(array.concat([min([n, i + 8])], downs))
	end := min([n, sig + 2])
	txt := concat("\n", [_code(lines[k]) | some k in numbers.range(start, end); not helpers.is_comment_line(lines[k])])
}

# ── The enclosing class ──────────────────────────────────────────────────

_class_re := `^\s*(?:(?:public|internal|private|protected|abstract|sealed|partial|static)\s+)*class\s+(\w+)(?:<[^>]*>)?\s*(?::\s*([^{]+))?`

_class_index(lines, i) := c if {
	cs := [k | some k in numbers.range(0, i); regex.match(_class_re, lines[k])]
	count(cs) > 0
	c := max(cs)
}

_class_attrs(lines, c) := concat("\n", [_code(lines[k]) |
	some k in numbers.range(max([0, c - 6]), c)
	not helpers.is_comment_line(lines[k])
	_attr_run(lines, k, c)
])

# Line k belongs to the contiguous attribute run directly above the class.
_attr_run(lines, c, c)

_attr_run(lines, k, c) if {
	k < c
	every j in numbers.range(k, c - 1) {
		_attr_or_skip(lines[j])
	}
}

_first_base(lines, c) := b if {
	m := regex.find_all_string_submatch_n(_class_re, lines[c], 1)[0]
	parts := split(trim_space(split(m[2], ",")[0]), ".")
	b := regex.replace(parts[count(parts) - 1], `<.*$`, "")
}

_api_base(b) if b in {"ControllerBase", "ApiController"}

# A base controller declared elsewhere in the project: protected by its own
# attribute, or itself an API controller.
_base_declares(base, re) if {
	some p, c in input.file_contents
	endswith(p, ".cs")
	contains(c, base)
	ls := split(c, "\n")
	some k, l in ls
	contains(l, "class")
	m := regex.find_all_string_submatch_n(_class_re, l, 1)
	count(m) > 0
	m[0][1] == base
	regex.match(re, concat("\n", [_class_attrs(ls, k), l]))
}

_class_mitigated(lines, c) if regex.match(concat("|", [_token_re, `\[\s*ApiController\b`, `\[\s*Consumes\s*\(`]), _class_attrs(lines, c))

_class_mitigated(lines, c) if _api_base(_first_base(lines, c))

_class_mitigated(lines, c) if {
	b := _first_base(lines, c)
	not b in {"Controller", "ControllerBase", "ApiController"}
	_base_declares(b, concat("|", [_token_re, `\[\s*ApiController\b`, `:\s*(?:[\w.]+\.)?(ControllerBase|ApiController)\b`]))
}

_mvc_controller(lines, c) if endswith(_first_base(lines, c), "Controller")

# A base named otherwise (AppControllerBase) that itself derives from an MVC
# controller in the project.
_mvc_controller(lines, c) if {
	b := _first_base(lines, c)
	not endswith(b, "Controller")
	not _api_base(b)
	regex.match(`^[A-Z]\w*$`, b)
	_base_declares(b, `class\s+\w+(?:<[^>]*>)?\s*:\s*(?:[\w.]+\.)?\w*Controller\s*(?:[,{<]|$)`)
}

# Web API 2 shares the attribute names.
_web_api_only(content) if {
	contains(content, "System.Web.Http")
	not contains(content, "System.Web.Mvc")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	_has_any(content, {"HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "AcceptVerbs"})
	not helpers.is_test_path(path)
	not _web_api_only(content)
	not _project_mitigated
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "AcceptVerbs"})
	not helpers.is_comment_line(line)
	verb := _verb(line)
	_reachable(verb, content)
	not regex.match(concat("|", [_token_re, _json_only_re]), _action_block(lines, i))
	c := _class_index(lines, i)
	_mvc_controller(lines, c)
	not _class_mitigated(lines, c)
	finding := {
		"rule_id": metadata.id,
		"message": "This MVC action accepts a cross-site form submission but does not validate an anti-forgery token, so another site can make a signed-in user's browser perform it (CSRF). Add [ValidateAntiForgeryToken], or [AutoValidateAntiforgeryToken] on the controller or as a global filter",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_638

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-638",
	"name": "Not Using Complete Mediation (cached authorization decision)",
	"description": "An authorization decision is memoised, so it is made once and then reused: a revoked permission, a demoted admin or a removed role keeps being granted until the process restarts. Reported: a Python function decorated with functools @lru_cache or @cache, a Java method annotated with Spring @Cacheable, and a JavaScript/TypeScript function wrapped in memoize/_.memoize/memoizee/moize/pMemoize/memoizeOne, when the function's name says it decides or loads access (has_permission/hasRole/has_access, is_admin/isAuthorized/is_allowed/is_owner, canX/can_x for an action on a resource such as canEdit/can_access_project, check_permission/checkAccess, get/load/fetch/lookup user permissions/roles/grants/acl/scopes, authorize; optionally prefixed user_/member_/account_, as in user_has_role), including TypeScript class fields (private readonly hasPermission = memoizeOne(...)). Not reported: names that describe a role or permission rather than decide one (get_role_display_name, getRoleLabel, get_permission_choices), capability probes (can_parse, canHandle),caches with an expiry (cachetools TTLCache, an @cached with a ttl), @cached_property (lives as long as one object, usually one request), cache eviction annotations, memoised functions whose names are not about access, and comments. Whether a configured cache manager adds a TTL to a @Cacheable region is not visible on the line and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-638/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [638],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["complete-mediation", "authorization", "caching", "cwe-638"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
}

_gate := {
	"py": `@(?:functools\.)?(?:lru_cache|cache)\b`,
	"java": `@Cacheable\b`,
	"js": `\b(?:memoize|memoizee|moize|pMemoize|memoizeOne)\s*\(`,
}

_authz_name(n) if {
	_authz_word(n)
	not regex.match(_static_lookup, n)
}

# Names that describe a role or permission rather than decide one
# (get_role_display_name, getPermissionLabel, get_permission_choices).
_static_lookup := `[Ll]abel|[Dd]isplay|[Dd]escription|[Tt]itle|[Cc]hoice|[Ii]con|[Cc]olou?r|[Nn]ames?$|_name|_text$|Text$`

_authz_word(n) if regex.match(`(?i)^(?:user_?|current_?user_?|member_?|account_?|principal_?)?(?:has_?(?:perm|permission|role|access|privilege|scope|authority|grant)|is_?(?:admin|authori[sz]ed|allowed|permitted|superuser|staff|owner|member|moderator)|check_?(?:perm|permission|access|auth\w*|role|acl|admin)|(?:get|load|fetch|find|lookup|resolve)_?(?:user_?|current_?user_?)?(?:perm|permission|role|grant|acl|authorit|privilege|scope|entitlement)s?|authori[sz]e|user_?(?:perm|permission|role|grant)s?)`, n)

# canX/can_x only for verbs that act on a resource someone may be denied
# (canEdit, can_access_project), not capability probes (canParse, canHandle).
_authz_word(n) if regex.match(`^(?:user_?|current_?user_?)?(?:can|Can)_?(?i:view|edit|access|read|write|delete|remove|manage|update|create|modify|admin|administer|see|approve|publish|invite|join|comment|post|upload|download|share|export|impersonate|moderate|perform|act|own|transfer|invoke|execute|run|use)`, n)

# The function or method a decorator/annotation at line i applies to: the
# first code line below it that is not another decorator.
_decorated_name(lang, lines, i) := n if {
	cands := [j |
		some j in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
		trim_space(lines[j]) != ""
		not helpers.is_comment_line(lines[j])
		not startswith(trim_space(lines[j]), "@")
	]
	count(cands) > 0
	n := _decl(lang, lines[cands[0]])
}

_decl("py", l) := n if {
	m := regex.find_all_string_submatch_n(`^\s*(?:async\s+)?def\s+(\w+)\s*\(`, l, 1)
	count(m) > 0
	n := m[0][1]
}

_decl("java", l) := n if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)*[\w<>\[\]?,. ]+\s+(\w+)\s*\(`, l, 1)
	count(m) > 0
	n := m[0][1]
}

_hit("py", lines, i) := n if {
	regex.match(`^\s*@(?:functools\.)?(?:lru_cache|cache)\b\s*(?:\([^)]*\))?\s*(#.*)?$`, lines[i])
	n := _decorated_name("py", lines, i)
	_authz_name(n)
}

_hit("java", lines, i) := n if {
	regex.match(`^\s*@Cacheable\b`, lines[i])
	n := _decorated_name("java", lines, i)
	_authz_name(n)
}

# JavaScript: the memoised function's own name, or the name it is assigned to.
_js_names(line) := {n |
	some re in [
		`^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*(?:\w+\.)?(?:memoize|memoizee|moize|pMemoize|memoizeOne)\s*\(`,
		`\b(?:module\.)?exports\.(\w+)\s*=\s*(?:\w+\.)?(?:memoize|memoizee|moize|pMemoize|memoizeOne)\s*\(`,
		`^\s*(?:(?:private|public|protected|readonly|static|override)\s+)*(\w+)\s*(?:[?!]?\s*:\s*[^=]+?)?\s*[:=]\s*(?:\w+\.)?(?:memoize|memoizee|moize|pMemoize|memoizeOne)\s*\(`,
		`\b(?:memoize|memoizee|moize|pMemoize|memoizeOne)\s*\(\s*(?:async\s+)?(?:function\s+)?(\w+)\s*[,)(]`,
	]
	some m in regex.find_all_string_submatch_n(re, line, 1)
	n := m[1]
	not n in {"async", "function"}
}

_hit("js", lines, i) := n if {
	ns := {x | some x in _js_names(lines[i]); _authz_name(x)}
	count(ns) > 0
	n := sort(ns)[0]
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	names := {n | n := _hit(lang, lines, i)}
	count(names) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Authorization decision %v is cached without expiry: a revoked permission or role keeps being granted. Check access on every request, or bound the cache with a short TTL and evict on change", [sort(names)[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

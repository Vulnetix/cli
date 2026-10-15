# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_524

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-524",
	"name": "Use of Cache Containing Sensitive Information: plaintext password cached",
	"description": "A plaintext password is put into a cache, where it outlives the request, is shared with everything else that reads the cache (another tenant, a debug endpoint, a Redis or memcached dump) and, for a memoised check, keeps authenticating after the password is changed. Reported: Python functools.lru_cache/cache, cachetools @cached and @memoize decorators on a function with a password parameter; Java Spring @Cacheable on a method with a password parameter; lodash/memoizee memoize() of a function with a password parameter; and a cache write (cache/redis/memcache/lru receivers: set, setex, add, put, hset, set_many) whose key or value is a password variable (password, raw_password, pwd, passphrase) or a request's password field (request.POST['password'], request.form.get('password'), req.body.password). Not reported: password hashes and digests (password_hash, hashedPassword), tokens and other values, flags and messages about passwords (password_reset_sent, passwordChangedAt, 'password changed'), cached functions without a password parameter, comments and test code. Model attributes such as user.password are not followed (they usually hold the hash).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-524/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [524],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["cache-sensitive", "password", "cwe-524"],
}

_exts := {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java"}

_in_scope(path) if {
	some e in _exts
	endswith(path, e)
	not endswith(path, ".min.js")
}

# A plaintext password variable: the name ends in password/passwd/passphrase
# (or is pwd) and does not describe a hash or a fact about the password.
_pw_name(name) if {
	l := lower(name)
	regex.match(`(?:pass(?:word|wd|phrase)|^pwd)$`, l)
	not regex.match(`hash|digest|crypt|enc|policy|reset|len|count|attempt|expir|change|field|label|hint|rule|confirm_?sent`, l)
}

# A request field holding the submitted password.
_pw_request := `(?i)\b(?:req\.(?:body|query)|request\.(?:form|POST|json|data|args|values|GET))(?:\.get\(\s*|\[\s*|\.)['"]?\w*pass(?:word|wd)['"]?`

_pw_arg(arg) if {
	a := trim_space(arg)
	regex.match(`^[A-Za-z_]\w*$`, a)
	_pw_name(a)
}

_pw_arg(arg) if regex.match(_pw_request, arg)

# Parameter names of a signature: `String password`, `password: str`,
# `password = None`, `raw_password`.
_param_pw(params) if {
	some p in split(params, ",")
	t := trim_space(regex.replace(regex.replace(p, `[:=].*$`, ""), `[\[\]\.*&]`, " "))
	words := [w | some w in split(t, " "); w != ""]
	count(words) > 0
	_pw_name(words[count(words) - 1])
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_signature(lines, i) := concat(" ", [lines[j] | some j in numbers.range(i, min([count(lines) - 1, i + 3]))])

# ── Memoised functions taking a password ─────────────────────────────────

_decorator_re := `^\s*@(?:functools\.)?(?:lru_cache|cache)\b|^\s*@(?:\w+\.)?(?:cached|memoize|memoized)\b|^\s*@Cacheable\b`

findings contains f if {
	some path, content in input.file_contents
	_in_scope(path)
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, content)
	regex.match(`@(?:functools\.)?(?:lru_cache|cache|cached|memoize|memoized|Cacheable)\b|@\w+\.(?:cached|memoize)\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "@")
	regex.match(_decorator_re, line)
	defs := [j |
		some j in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
		not regex.match(`^\s*@`, lines[j])
		trim_space(lines[j]) != ""
	]
	count(defs) > 0
	sig := _signature(lines, defs[0])
	m := regex.find_all_string_submatch_n(`(?:\bdef\s+\w+|\w+)\s*\(([^)]*)\)`, sig, 1)
	count(m) > 0
	_param_pw(m[0][1])
	f := _finding(path, i, line, "This cache memoises a function by its password argument, so plaintext passwords are kept in the cache as keys and a cached result keeps authenticating after the password changes. Do not cache credential checks; cache by a non-secret key if at all")
}

findings contains f if {
	some path, content in input.file_contents
	_in_scope(path)
	contains(content, "memoize")
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "memoize")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bmemoize(?:e)?\(\s*(?:async\s*)?(?:function\s*\w*\s*)?\(([^)]*)\)`, line, 1)
	count(m) > 0
	_param_pw(m[0][1])
	f := _finding(path, i, line, "memoize() caches this function by its password argument, keeping plaintext passwords in memory and serving cached results after the password changes. Do not memoise credential checks")
}

# ── Cache writes of a password ───────────────────────────────────────────

_write_re := `(?i)\b(\w*(?:cache|redis|memcache|memcached|lru)\w*)\.(?:set|setex|psetex|add|put|hset|hmset|set_many|setnx)\(\s*(.*)$`

findings contains f if {
	some path, content in input.file_contents
	_in_scope(path)
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, content)
	regex.match(`(?i)(?:cache|redis|memcache|lru)\w*\.(?:set|setex|psetex|add|put|hset|hmset|set_many|setnx)\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_write_re, line, 1)
	count(m) > 0
	_args_have_pw(m[0][2])
	f := _finding(path, i, line, "A plaintext password is written to a cache, where it outlives the request and is readable by anything that can read the cache. Never cache passwords; keep only what the next step needs, such as a hash or an opaque reference")
}

_args_have_pw(args) if {
	some a in split(args, ",")
	_pw_arg(regex.replace(a, `\)+\s*;?\s*$`, ""))
}

_args_have_pw(args) if regex.match(_pw_request, args)

# A Redis/memcached client bound to a short name (r = redis.Redis(),
# const client = createClient()) is a cache receiver too.
_client_ctor_re := `(?m)^\s*(?:const\s+|let\s+|var\s+|self\.|(?:private\s+|final\s+|static\s+)*[A-Z][\w<>]*\s+)?(\w+)\s*(?::\s*\w+\s*)?=\s*(?:await\s+)?(?:new\s+)?(?:redis\.(?:Strict)?Redis(?:\.from_url)?|redis\.from_url|aioredis\.from_url|Redis(?:\.from_url)?|(?:redis\.)?createClient|memcache\.Client|pymemcache\.(?:client\.)?(?:base\.|hash\.)?(?:Hash)?Client|HashClient|Memcached|new\s+Jedis|Jedis)\(`

findings contains f if {
	some path, content in input.file_contents
	_in_scope(path)
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, content)
	not helpers.is_test_path(path)
	clients := {c[1] |
		some c in regex.find_all_string_submatch_n(_client_ctor_re, content, -1)
		not regex.match(`(?i)cache|redis|memcache|lru`, c[1])
	}
	count(clients) > 0
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pass(?:word|wd|phrase)|pwd`, line)
	not helpers.is_comment_line(line)
	some name in clients
	m := regex.find_all_string_submatch_n(concat("", [`\b`, name, `\.(?:set|setex|psetex|add|put|hset|hmset|set_many|setnx)\(\s*(.*)$`]), line, 1)
	count(m) > 0
	_args_have_pw(m[0][1])
	f := _finding(path, i, line, "A plaintext password is written to a cache, where it outlives the request and is readable by anything that can read the cache. Never cache passwords; keep only what the next step needs, such as a hash or an opaque reference")
}

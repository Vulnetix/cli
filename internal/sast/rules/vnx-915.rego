# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_915

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-915",
	"name": "Mass assignment: the whole request body is written onto a model",
	"description": "The request body is copied wholesale onto a persistent object, so a client can set any field the model has (role, isAdmin, price, ownerId) (CWE-915). Reported in JavaScript/TypeScript: Object.assign(target, ..., req.body) onto a non-empty target; new Model(req.body); ORM writes create/build/insert/insertOne/insertMany/update/updateOne/updateMany/findByIdAndUpdate/findOneAndUpdate/upsert/set/merge given req.body, req.body.<member>, req.query or ctx.request.body as a direct argument or spread into an object literal ({...req.body, owner}); Prisma create/update/upsert with data: req.body; MongoDB update operators ({ $set: req.body }) in update*/findOneAndUpdate/findByIdAndUpdate; and the same through a variable assigned from the bare body in the 15 lines above. Not reported: explicit fields (create({ name: req.body.name })), bodies filtered through pick/omit or a validator, Object.assign({}, ...) copies, hash/HMAC/cipher update(), built-in constructors (URL, Error, Buffer), comments and strings. Ruby mass assignment (permit!, raw params hashes, params.to_unsafe_h, a permit list admitting admin/role) is reported by VNX-RUBY-006, not here. Overlaps VNX-349 (merges into trusted objects).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-915/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [915],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["mass-assignment", "cwe-915"],
}

_js_exts := {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}

_body := `(?:\b(?:req|request)\.body(?:\.[A-Za-z_]\w*)?|\b(?:req|request)\.query|\bctx\.request\.body)`

_body_gate := `\b(?:req|request)\.(?:body|query)\b|\bctx\.request\.body\b`

_orm := `create|build|insert|insertOne|insertMany|update|updateOne|updateMany|findByIdAndUpdate|findOneAndUpdate|upsert|set|merge`

_builtin := {"Error", "TypeError", "RangeError", "URL", "URLSearchParams", "Buffer", "Date", "Map", "Set", "WeakMap", "Promise", "RegExp", "String", "Number", "Boolean", "Blob", "Headers", "Request", "Response", "FormData", "Array", "Uint8Array", "TextEncoder", "TextDecoder"}

_hash_recv := `(?i)^(?:h|hash\w*|hmac\w*|md5|sha\w*|cipher|decipher|hasher|digest|signer|sign|verifier|verify)$`

# Variables that hold the bare body: const changes = req.body / { ...req.body }
_body_vars(lines, i) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(concat("", [`=\s*(?:\{\s*\.\.\.)?`, _body, `\s*\}?\s*;?\s*$`]), prev)
	v := helpers.assigned_first(prev)
}

_src(lines, i) := s if {
	vs := _body_vars(lines, i)
	count(vs) > 0
	s := concat("", [`(?:`, _body, `|\b(?:`, concat("|", vs), `)\b)`])
}

_src(lines, i) := _body if count(_body_vars(lines, i)) == 0

_js_hit(code, src) if {
	m := regex.find_all_string_submatch_n(concat("", [`\bObject\.assign\(\s*([\w\.\[\]]+)\s*,(?:\s*[\w\.]+\s*,)*\s*`, src, `\s*\)`]), code, 1)
	count(m) > 0
}

_js_hit(code, src) if {
	m := regex.find_all_string_submatch_n(concat("", [`\bnew\s+([A-Z]\w*)\s*\(\s*`, src, `\s*[,)]`]), code, -1)
	some x in m
	not x[1] in _builtin
}

_js_hit(code, src) if {
	m := regex.find_all_string_submatch_n(concat("", [`([\w\$]+)\.(?:`, _orm, `)\s*\(\s*(?:[\w\.\[\]'"]+\s*,\s*)?(?:`, src, `\s*[,)]|\{\s*\.\.\.`, src, `\b)`]), code, -1)
	some x in m
	not regex.match(_hash_recv, x[1])
}

_js_hit(code, src) if {
	regex.match(concat("", [`\.(?:create|update|upsert|createMany|updateMany)\s*\(\s*\{.*\bdata\s*:\s*(?:`, src, `\s*[,}]|\{\s*\.\.\.`, src, `\b)`]), code)
}

# MongoDB update operators: updateOne({ _id }, { $set: req.body })
_js_hit(code, src) if {
	regex.match(concat("", [`\.(?:update\w*|findByIdAndUpdate|findOneAndUpdate)\s*\(.*\$set\s*:\s*(?:`, src, `\s*[,}]|\{\s*\.\.\.`, src, `\b)`]), code)
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _js_exts
	endswith(path, ext)
	not endswith(path, ".min.js")
	regex.match(_body_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(`\bObject\.assign\(|\bnew\s+[A-Z]|\.(?:create|build|insert\w*|update\w*|findByIdAndUpdate|findOneAndUpdate|upsert|set|merge)\s*\(`, line)
	code := regex.replace(line, `"[^"]*"|'[^']*'`, `""`)
	_js_hit(code, _src(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "The whole request body is written onto a model (mass assignment): a client can set any field it has, such as role, isAdmin or price. Copy the allowed fields explicitly",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Ruby mass assignment (permit!, raw params hashes, to_unsafe_h, a permit list
# admitting a privilege attribute) is the same weakness and is reported by
# VNX-RUBY-006, which follows params through variables and multi-line permit
# lists; this rule does not read Ruby.

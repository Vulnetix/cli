# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_841

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-841",
	"name": "Improper Enforcement of Behavioral Workflow",
	"description": "Workflow state decided by the client instead of by the server's own process. Two shapes are reported. (1) A workflow-state field set from a request value, directly or through one assignment: order.status = req.body.status, Order.objects.filter(...).update(status=request.POST[\"status\"]), loan.setStatus(...status...) with status a @RequestParam or order.setStatus(body.getStatus()) with body a @RequestBody, order.is_paid / .approved / .verified / .payment_status = request value. status, stage, step, state and completed count only on a workflow object (order, payment, checkout, booking, loan, application, ticket, transfer and similar), so a profile status or an address state is not reported. (2) An if that advances the workflow because the request says so: if request.args.get(\"payment_status\") == \"success\", if (req.query.paid === 'true'), if (\"confirmed\".equals(step)) with step a request parameter, followed within six lines by a status change, setStatus, fulfil/ship/approve/capture call. Java, JavaScript/TypeScript and Python. Not reported: read queries that filter by status (Order.find({ status: req.query.status }), Order.objects.filter(status=...)) with no update on the line, state set from a constant after a server-side check (a provider lookup, a verified webhook), a requested transition checked against an allowed-transitions table, handlers behind an admin/role check or under an admin path, response status codes, and the pattern in comments or strings. Flows through helper functions are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-841/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [841],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["flow-ordering", "workflow", "state-machine", "cwe-841"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_source := {
	"js": `\breq(?:uest)?\.(?:body|query|params)\b`,
	"py": `\brequest\.(?:json|form|args|values|data|GET|POST|get_json)\b`,
	"java": `\b\w*[rR]eq(?:uest)?\.getParameter(?:Values)?\s*\(`,
}

_file_gate(lang, content) if regex.match(_source[lang], content)

_file_gate("java", content) if regex.match(`@(?:RequestParam|PathVariable|RequestHeader|RequestBody)\b`, content)

_strong :=`(?i)^(?:paid|is_?paid|payment_?status|order_?status|approved|is_?approved|verified|is_?verified|workflow_?state)$`

_weak := `(?i)^(?:status|stage|step|state|completed|is_?completed)$`

_workflow := `(?i)order|payment|invoice|checkout|purchase|transaction|txn|booking|reservation|application|claim|refund|shipment|subscription|loan|approval|ticket|cart|basket|workflow|wizard|onboarding|kyc|delivery|withdraw|transfer`

_flag := `(?i)^(?:paid|is_?paid|payment_?status|payment_?success|success|status|approved|verified|completed|step|stage|result)$`

# String literals containing whitespace are prose.
_strip(line) := regex.replace(line, concat("", [`"(?:\\.|[^"\\\n])*(?:[\s()=]|\\.)(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*(?:[\s()=]|\\.)(?:\\.|[^'\\\n])*'|`, "`[^`\\n]*`"]), `""`)

_field_ok(field, _) if regex.match(_strong, field)

_field_ok(field, ctx) if {
	regex.match(_weak, field)
	regex.match(_workflow, ctx)
}

# [field, context, rhs] for each workflow-state write on a line.
_writes(line) := {[f, ctx, rhs] |
	some m in regex.find_all_string_submatch_n(`(\w+)\s*\.\s*(\w+)\s*=\s*([^=].*)$`, line, -1)
	f := m[2]
	ctx := m[1]
	rhs := m[3]
} | {[f, ctx, rhs] |
	some m in regex.find_all_string_submatch_n(`(\w+)\.set(Status|Stage|Step|State|Paid|IsPaid|Approved|Verified|PaymentStatus|OrderStatus|WorkflowState|Completed)\s*\((.*)`, line, -1)
	f := lower(m[2])
	ctx := m[1]
	rhs := m[3]
} | {[f, ctx, rhs] |
	not _read_query(line)
	some m in regex.find_all_string_submatch_n(`[\{,\(]\s*['"]?(\w+)['"]?\s*[:=]\s*([^,}=\s()][^,}()]*(?:\([^()]*\)[^,}()]*)*)`, line, -1)
	f := m[1]
	ctx := line
	rhs := m[2]
}

# A query that only reads by status (Order.find({ status: req.query.status }),
# Order.objects.filter(status=...)) filters a listing; it changes no state.
_read_query(line) if {
	regex.match(`\.(?:find\w*|filter(?:_by)?|where|count\w*|exclude|select|aggregate|exists|get)\s*\(`, line)
	not regex.match(`(?i)\.(?:update\w*|save|create|insert\w*|upsert|set\w*|increment|bulk\w*)\s*\(|\$set\b`, line)
}

_destructured(line) := {n |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?req(?:uest)?\.(?:body|query|params)\b`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	ps := split(trim_space(part), ":")
	n := trim_space(ps[count(ps) - 1])
	n != ""
}

_tainted(lang, lines, i) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_source[lang], prev)
	v := helpers.assigned_first(prev)
} | {v |
	lang == "js"
	some j in numbers.range(max([0, i - 15]), i - 1)
	some v in _destructured(lines[j])
} | {v |
	lang == "java"
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], "@")
	some m in regex.find_all_string_submatch_n(`@(?:RequestParam|PathVariable|RequestHeader|RequestBody)(?:\([^)]*\))?\s+(?:final\s+)?(?:@Valid(?:ated)?\s+)?[\w<>]+\s+(\w+)`, lines[j], -1)
	v := m[1]
}

_carries(lang, rhs, _, _) if regex.match(_source[lang], rhs)

_carries(lang, rhs, lines, i) if {
	some v in _tainted(lang, lines, i)
	regex.match(concat("", [`\b`, v, `\b`]), rhs)
}

_guard := `(?i)allowed_?transitions|valid_?transitions|can_?transition|transitions?\s*\[|transitions?\.|\bis_?admin\b|hasRole|hasAuthority|PreAuthorize|RolesAllowed|Secured\(|admin_required|staff_member_required|permission_required|require_?admin|ensure_?admin|requireRole`

_guarded(path, _, _) if regex.match(`(?i)(^|/)admin`, path)

_guarded(_, lines, i) if {
	regex.match(_guard, helpers.code_window(lines, i, 30, 0))
}

# Direct request read of a flag-named field in a condition.
_flag_read("js", line) if {
	some m in regex.find_all_string_submatch_n(`\breq(?:uest)?\.(?:body|query|params)(?:\.|\[\s*['"])(\w+)`, line, -1)
	regex.match(_flag, m[1])
}

_flag_read("py", line) if {
	some m in regex.find_all_string_submatch_n(`\brequest\.(?:json|form|args|values|data|GET|POST)\s*(?:\.get\s*\(\s*|\[\s*)['"](\w+)['"]`, line, -1)
	regex.match(_flag, m[1])
}

_flag_read("java", line) if {
	some m in regex.find_all_string_submatch_n(`getParameter\s*\(\s*"(\w+)"`, line, -1)
	regex.match(_flag, m[1])
}

_cond_on_client(lang, line, _, _) if _flag_read(lang, line)

_cond_on_client(lang, line, lines, i) if {
	some v in _tainted(lang, lines, i)
	regex.match(_flag, v)
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

_transition := `\.(?:status|stage|paid|is_paid|isPaid|approved|verified)\s*=[^=]|\.set(?:Status|Stage|Paid|Approved|Verified)\s*\(|\b(?:fulfil|fulfill|ship|markPaid|mark_paid|mark_as_paid|approve|capture)\w*\s*\(`

_hit(lang, lines, i, line, _) if {
	some w in _writes(line)
	_field_ok(w[0], w[1])
	_carries(lang, w[2], lines, i)
}

_hit(lang, lines, i, line, _) if {
	regex.match(`^\s*(?:\}\s*)?(?:else\s+)?(?:if|elif)\b`, line)
	_cond_on_client(lang, line, lines, i)
	regex.match(_transition, helpers.code_window(lines, i + 1, 0, 5))
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_file_gate(lang, content)
	regex.match(`(?i)status|stage|step|paid|approved|verified|completed|state`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`(?i)status|stage|step|paid|approved|verified|completed|state|success|result`, raw)
	not helpers.is_comment_line(raw)
	line := _strip(raw)
	_hit(lang, lines, i, line, raw)
	not _guarded(path, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Workflow state is taken from the request: the client can skip or reorder steps (mark an order paid, approved or shipped) without the server's own process having run. Derive the next state on the server from verified facts and check the transition is allowed from the current state",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": raw,
	}
}

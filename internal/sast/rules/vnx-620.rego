# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_620

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-620",
	"name": "Password change that does not verify the current password",
	"description": "Reports a password write inside a change-password handler that reads the new password from the request but never verifies the user's current password first. The write is set_password()/setPassword(), an assignment to <user>.password (C# Password/PasswordHash too; or password_hash/passwordHash/hashed_password), an ORM update of password (update, updateOne, findByIdAndUpdate, a Prisma update whose data: block sets password within three lines), a $set of password, an UPDATE ... SET password statement, or in Java and C# a service call such as userService.changeUserPassword(user, pw) or UpdateCustomerPassword(id, pw) that does not pass an old/current password (JavaScript calls of that shape are usually front-end API clients and are not reported); the handler is recognised by a change/update/new-password name or route in the 40 lines above, together with request access ([HttpPost]/[FromBody] actions, request, Request, req, query, @RequestBody, getParameter, params, body, form). Verification means a check_password/checkpw/password_verify/bcrypt compare/compareX() (user.comparePassword(old))/PasswordEncoder.matches/verify/authenticate/Membership ValidateUser call, or a comparison against an old/current password variable; a check guarded by 'if (currentPassword && ...)' only runs when the client sends the current password, so it does not count. Without the check, a hijacked session, a CSRF request or an XSS payload can take over the account permanently. Not reported: handlers that verify the current password, Django's PasswordChangeForm, password-reset flows (a reset token or code), invitation and activation flows, administrator endpoints, registration, test files, comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-620/",
	"languages": ["csharp", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [620],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["unverified-password-change", "authentication", "cwe-620"],
}

_exts := {".py", ".js", ".ts", ".mjs", ".cjs", ".java", ".cs"}

# The write of a new password.
_sink_re := `(\.set_?[Pp]assword\s*\(|\.(password|passwd|password_hash|hashed_password|passwordHash|pwd)\s*=[^=]|(?i:\.\w*update\w*)\s*\(.*\bpass(word|wd)(_?[hH]ash)?\s*[:=][^=]|\$set\s*:\s*\{[^}]*\bpassword\s*:|(?i:\bUPDATE\s+[\w\x60"\.]+\s+SET\s+[^;'"]*\bpass(word|wd)?\w*\s*=))`

_context_re := `(?i)(change|update|edit|new)[_-]?pass(word|wd)?|pass(word|wd)?[_-]?(change|update|edit)`

_request_re := `(?i)\brequest\b|\[Http(Post|Put|Patch)\b|\[From(Body|Form)\]|\breq\b|\bquery\b|getParameter\s*\(|@Request(Body|Param)|@ModelAttribute|HttpServletRequest|\bparams\b|\bbody\b|cleaned_data|\bform\b`

# An explicit check of the current password.
_verify_call_re := `(?i)check_?password\w*\s*\(|checkpw\s*\(|\bcompare\w*\s*\(|ValidateUser\s*\(|password_verify\s*\(|\.matches\s*\(|verify_?password\s*\(|\bverify\s*\(|is_?(password_?)?valid_?password\s*\(|isPasswordValid\s*\(|\bauthenticate\s*\(|check_password_hash\s*\(|PasswordChangeForm`

_old_name_re := `(?i)\b\w*(old|current|curr|existing|previous|prev)_?(pass(word|wd)?|pwd|pw)\w*\b`

_compare_re := `(==|!=|\.equals\s*\(|\bis\s+not\b|\bnot\s+in\b)`

# `if (currentPassword && ...)` / `if current_password and ...`: the check
# only runs when the client chooses to send the current password.
_optional_re := `(?i)\bif\s*\(?\s*!?\s*(\w+\.)*\w*(old|current|curr|existing)\w*\s*(&&|\band\b)`

_skip_ctx_re := `(?i)reset|forgot|recover|invit(e|ation)|activat|onboard|\badmin|is_?superuser|hasRole\s*\(|hasAuthority\s*\(|ROLE_ADMIN|staff_member_required`

_verifies(win_lines) if {
	some l in win_lines
	regex.match(_verify_call_re, l)
	not regex.match(_optional_re, l)
}

_verifies(win_lines) if {
	some l in win_lines
	regex.match(_old_name_re, l)
	regex.match(_compare_re, l)
	not regex.match(_optional_re, l)
}

_has_ext(path) if {
	some ext in _exts
	endswith(path, ext)
}

findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path)
	not helpers.is_test_path(path)
	regex.match(_context_re, content)
	regex.match(`(?i)password|passwd`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)pass`, line)
	not helpers.is_comment_line(line)
	_sink(lines, i, path, line)
	start := max([0, i - 40])
	before := [l | some j in numbers.range(start, i); l := lines[j]; not helpers.is_comment_line(l)]
	win := concat("\n", before)
	regex.match(_context_re, win)
	regex.match(_request_re, win)
	not regex.match(_skip_ctx_re, win)
	not _verifies(before)
	finding := {
		"rule_id": metadata.id,
		"message": "Password is changed without verifying the user's current password. Require and check the current password (check_password / bcrypt.compare / PasswordEncoder.matches) before writing the new one",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_sink(_, _, _, line) if regex.match(_sink_re, line)

# prisma.user.update({ where: ..., data: { passwordHash: hash } }) across lines
_sink(lines, i, _, line) if {
	regex.match(`\bdata\s*:\s*\{[^}]*\bpass(word|wd)(_?[hH]ash)?\s*:`, line)
	win := concat("\n", array.slice(lines, max([0, i - 3]), i + 1))
	regex.match(`\.update(Many)?\s*\(`, win)
}

# Server-side service call: userService.changeUserPassword(user, newPassword),
# du.UpdateCustomerPassword(id, pw). Not in JavaScript, where the same call is
# usually a front-end client of the API. A call that passes the old/current
# password (Membership ChangePassword(old, new), ChangePasswordAsync(user,
# model.OldPassword, ...)) verifies it.
_sink(_, _, path, line) if {
	regex.match(`\.(java|cs)$`, path)
	regex.match(`\.(?i:change|update|save)\w*(?i:password)(Async)?\s*\(`, line)
	not regex.match(_old_name_re, line)
}

# C# properties are capitalised: user.Password = hash, account.PasswordHash = hash.
_sink(_, _, path, line) if {
	endswith(path, ".cs")
	regex.match(`\.(Password|PasswordHash|HashedPassword)\s*=[^=>]`, line)
}

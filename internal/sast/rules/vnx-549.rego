# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_549

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-549",
	"name": "Missing Password Field Masking",
	"description": "A password is collected in a field that shows what is typed. Reported: an HTML/JSX/template <input>, Blazor <InputText> or Material UI <TextField> (on one line or spread over several, attribute values quoted or not) whose name, id, formControlName, v-model, ng-model, @bind-Value or autocomplete names a password (password, passwd, pwd, passphrase, current-password, new-password, as the last word of the name) and whose type is text or absent (absent means text); a Rails f.text_field/text_field_tag for a password attribute; an ASP.NET MVC Html.TextBoxFor(m => m.Password) or Html.TextBox(\"Password\"); a Django forms.CharField for a password field with no PasswordInput widget, and a WTForms StringField/TextField for one; and an Android layout EditText whose id or hint names a password with android:inputType=\"text\" or \"textVisiblePassword\". Not reported: type=\"password\", hidden inputs, a type bound at run time (a show-password toggle such as :type or type={visible ? 'text' : 'password'}), password_field/PasswordField/PasswordInput, Django model fields (models.CharField), fields that only mention passwords (password_hint, password_strength, password_reset_token, an id such as password-storage-salt), Html.PasswordFor, labels and placeholders, HTML comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-549/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [549],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["password-masking", "cwe-549"],
}

_markup_exts := {
	".html", ".htm", ".xhtml", ".ejs", ".erb", ".jsx", ".tsx", ".vue", ".svelte", ".php", ".jsp", ".jspx",
	".cshtml", ".razor", ".hbs", ".handlebars", ".mustache", ".twig", ".j2", ".jinja", ".jinja2", ".njk",
	".gohtml", ".tmpl", ".liquid", ".astro",
}

_markup(path) if {
	some ext in _markup_exts
	endswith(path, ext)
}

# A field name that is a password, not something about one.
_password_name(v) if {
	regex.match(`(?i)pass(word|wd|phrase)|(^|[^a-z])pwd([^a-z]|$)|^pw$`, v)
	not regex.match(`(?i)hint|strength|policy|length|token|reset_?(link|url|code)|question|label|rule|expir|changed|_at$|count|attempt|^show|toggle|visible|reveal|confirm_?sent|enabled|required`, v)
	_password_last_word(v)
}

# The password word is the last word of a separated name (login_password,
# user[password], new-password, password_confirmation, answer_pwd2), so an id
# such as password-storage-salt, which names something about passwords, is not
# taken for the password field itself. A camelCase name is one word here.
_password_last_word(v) if {
	words := [w | some w in regex.split(`[^A-Za-z0-9]+`, regex.replace(v, `[\]\d\s]+$`, "")); w != ""]
	count(words) > 0
	last := words[count(words) - 1]
	regex.match(`(?i)pass(word|wd|phrase)|pwd|^pw$|^(confirm\w*|confirmation|again|repeat|verify|current|new|old)$`, last)
}

# ── HTML / JSX / templates ───────────────────────────────────────────────

# Elements whose type defaults to text: HTML <input>, Blazor <InputText> and
# Material UI <TextField>.
_input_re := `<(input|InputText|TextField)\b`

# The tag text from the element's opening to the first `>` (at most eight lines).
_tag(lines, i, tok) := t if {
	start := substring(lines[i], indexof(lines[i], tok), -1)
	last := min([count(lines) - 1, i + 7])
	ends := [k |
		some k in numbers.range(i, last)
		seg := concat(" ", array.concat([start], array.slice(lines, i + 1, k + 1)))
		contains(seg, ">")
	]
	e := min(array.concat(ends, [last]))
	full := concat(" ", array.concat([start], array.slice(lines, i + 1, e + 1)))
	t := substring(full, 0, indexof(full, ">") + 1)
}

_unmasked_type(t) if not regex.match(`(?i)(^|[\s:\[@])(v-bind:)?\[?type\]?\s*=`, t)

_unmasked_type(t) if regex.match(`(?i)(^|\s)type\s*=\s*(["']?)text(["'\s/>]|$)`, t)

_field_attr := `(name|id|formcontrolname|v-model|ng-model|autocomplete|bind-value|bind)`

_password_field(t) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(?i)\b`, _field_attr, `\s*=\s*["'{]([^"'}]*)["'}]`]), t, -1)
	_password_name(m[2])
}

# Unquoted attribute values (<input type=text name=password>).
_password_field(t) if {
	some m in regex.find_all_string_submatch_n(`(?i)(?:^|\s)(name|id)\s*=\s*([^\s"'{>]+)`, t, -1)
	_password_name(m[2])
}

findings contains finding if {
	some path, content in input.file_contents
	_markup(path)
	regex.match(_input_re, content)
	regex.match(`(?i)pass(word|wd|phrase)|pwd|\bpw\b`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "<")
	tm := regex.find_all_string_submatch_n(_input_re, line, 1)
	count(tm) > 0
	not regex.match(`^\s*<!--`, line)
	not regex.match(concat("", [`<!--[^>]*`, _input_re]), line)
	t := _tag(lines, i, tm[0][0])
	_unmasked_type(t)
	_password_field(t)
	finding := _finding(path, i, line)
}

# ── Rails: f.text_field :password / text_field_tag :password ─────────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".erb")
	contains(content, "text_field")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "text_field")
	m := regex.find_all_string_submatch_n(`\btext_field(?:_tag)?\s*\(?\s*[:'"](\w+)`, line, -1)
	some x in m
	_password_name(x[1])
	finding := _finding(path, i, line)
}

# ── ASP.NET MVC: @Html.TextBoxFor(m => m.Password) / Html.TextBox("Password")

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cshtml")
	contains(content, "TextBox")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "TextBox")
	some x in regex.find_all_string_submatch_n(`\bTextBox(?:For)?\s*\(\s*(?:\w+\s*=>\s*\w+\.(\w+)|"(\w+)")`, line, -1)
	_password_name(concat("", [x[1], x[2]]))
	finding := _finding(path, i, line)
}

# ── Django forms.CharField / WTForms StringField for a password ──────────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`CharField|StringField|TextField`, content)
	regex.match(`(?i)passw|pwd`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`^\s*(\w+)\s*=\s*(?:forms\.|wtforms\.)?(CharField|StringField|TextField)\s*\(`, line, 1)
	count(m) > 0
	_password_name(m[0][1])
	not contains(_py_call(lines, i), "PasswordInput")
	finding := _finding(path, i, line)
}

_py_call(lines, i) := t if {
	last := min([count(lines) - 1, i + 6])
	ends := [k |
		some k in numbers.range(i, last)
		seg := concat(" ", array.slice(lines, i, k + 1))
		strings.count(seg, "(") <= strings.count(seg, ")")
	]
	e := min(array.concat(ends, [last]))
	t := concat(" ", array.slice(lines, i, e + 1))
}

# ── Android layout: an EditText for a password with inputType="text" ─────

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".xml")
	contains(path, "res/layout")
	contains(content, "android:inputType")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`android:inputType\s*=\s*"text(VisiblePassword)?"`, line)
	start := max([0, i - 8])
	opens := [j | some j in numbers.range(start, i); contains(lines[j], "<")]
	count(opens) > 0
	o := opens[count(opens) - 1]
	# The element's own attributes: from its opening line to the inputType line,
	# then onward only until the next element begins.
	tail := [lines[k] |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
		not contains(line, ">")
		every q in numbers.range(i + 1, k) {
			not contains(lines[q], "<")
		}
	]
	el := concat(" ", array.concat(array.slice(lines, o, i + 1), tail))
	some m in regex.find_all_string_submatch_n(`android:(?:id|hint)\s*=\s*"@(?:\+?id|string)/(\w+)"`, el, -1)
	_password_name(m[1])
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "A password is entered into a field that displays it in clear text, where anyone looking at the screen, a screen recording or a screenshot can read it. Use type=\"password\" (password_field, PasswordInput, PasswordField, inputType=\"textPassword\") and offer an explicit show-password toggle if needed",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

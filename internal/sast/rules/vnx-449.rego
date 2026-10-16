# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_449

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-449",
	"name": "The UI Performs the Wrong Action",
	"description": "Reports a C/C++ confirmation dialog whose answer is compared with a button the dialog does not have, so the confirmed branch never runs (or always runs): a Win32 MessageBox/MessageBoxEx with an explicit MB_YESNO, MB_YESNOCANCEL, MB_OKCANCEL, MB_RETRYCANCEL, MB_ABORTRETRYIGNORE, MB_CANCELTRYCONTINUE or MB_OK button set, or only icon/modality flags (which shows the default lone OK button), whose result is tested against another ID (MB_YESNO == IDOK), a Qt QMessageBox::question/warning/information/critical whose result is tested against a StandardButton outside its buttons (question() offers Yes and No by default, the others Ok), and a GTK gtk_message_dialog_new with GTK_BUTTONS_* whose gtk_dialog_run response is tested against a GTK_RESPONSE_* it cannot return. The comparison is reported in the dialog call itself, through the variable assigned from it, or in a switch on it (including switch (gtk_dialog_run(...))), within the next lines. Not reported: comparisons with a button the dialog offers, button sets held in a variable (Win32 flags or a Qt buttons argument), GTK dialogs whose buttons are added later, GTK_RESPONSE_DELETE_EVENT/NONE, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-449/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [449],
	"capec": [],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["wrong-function", "dialog", "cwe-449"],
}

_c_file(path) if regex.match(`\.(?:c|cc|cpp|cxx|c\+\+|h|hh|hpp|hxx)$`, path)

_call_re := `\bMessageBox(?:Ex)?[AW]?\s*\(|\bQMessageBox::(?:question|warning|information|critical)\s*\(|\bgtk_message_dialog_new(?:_with_markup)?\s*\(`

_kind(line) := "win" if regex.match(`\bMessageBox(?:Ex)?[AW]?\s*\(`, line)

_kind(line) := "qt" if regex.match(`\bQMessageBox::(?:question|warning|information|critical)\s*\(`, line)

_kind(line) := "gtk" if regex.match(`\bgtk_message_dialog_new(?:_with_markup)?\s*\(`, line)

_win_sets := {
	"OK": {"OK"},
	"OKCANCEL": {"OK", "CANCEL"},
	"YESNO": {"YES", "NO"},
	"YESNOCANCEL": {"YES", "NO", "CANCEL"},
	"RETRYCANCEL": {"RETRY", "CANCEL"},
	"ABORTRETRYIGNORE": {"ABORT", "RETRY", "IGNORE"},
	"CANCELTRYCONTINUE": {"CANCEL", "TRYAGAIN", "CONTINUE"},
}

_win_ids := {"OK", "CANCEL", "YES", "NO", "RETRY", "ABORT", "IGNORE", "TRYAGAIN", "CONTINUE"}

_gtk_sets := {
	"OK": {"OK"},
	"CLOSE": {"CLOSE"},
	"CANCEL": {"CANCEL"},
	"YES_NO": {"YES", "NO"},
	"OK_CANCEL": {"OK", "CANCEL"},
}

_gtk_ids := {"OK", "CLOSE", "CANCEL", "YES", "NO", "APPLY", "HELP"}

_qt_ids := {
	"Ok", "Open", "Save", "Cancel", "Close", "Discard", "Apply", "Reset", "RestoreDefaults",
	"Help", "SaveAll", "Yes", "YesToAll", "No", "NoToAll", "Abort", "Retry", "Ignore",
}

# Index of the line holding the statement's ';' (the call may span lines).
_stmt_end(lines, i) := e if {
	ends := [k | some k in numbers.range(i, min([count(lines) - 1, i + 6])); contains(lines[k], ";")]
	count(ends) > 0
	e := ends[0]
}

_stmt(lines, i, e) := concat(" ", [lines[k] | some k in numbers.range(i, e)])

# The buttons the dialog can return.
_allowed("win", stmt) := s if {
	ms := regex.find_all_string_submatch_n(`\bMB_(OK|OKCANCEL|YESNO|YESNOCANCEL|RETRYCANCEL|ABORTRETRYIGNORE|CANCELTRYCONTINUE)\b`, stmt, -1)
	names := {m[1] | some m in ms}
	count(names) == 1
	some n in names
	s := _win_sets[n]
}

# Flags given literally (an icon, modality or default-button flag) with no button
# set: Windows shows the default, a lone OK button.
_allowed("win", stmt) := {"OK"} if {
	not regex.match(`\bMB_(?:OK|OKCANCEL|YESNO|YESNOCANCEL|RETRYCANCEL|ABORTRETRYIGNORE|CANCELTRYCONTINUE)\b`, stmt)
	regex.match(`\bMB_(?:ICON\w+|APPLMODAL|SYSTEMMODAL|TASKMODAL|TOPMOST|SETFOREGROUND|DEFBUTTON\d)\b`, stmt)
}

_allowed("gtk", stmt) := s if {
	ms := regex.find_all_string_submatch_n(`\bGTK_BUTTONS_(OK|CLOSE|CANCEL|YES_NO|OK_CANCEL)\b`, stmt, -1)
	count(ms) == 1
	s := _gtk_sets[ms[0][1]]
}

_allowed("qt", stmt) := s if {
	call := regex.replace(stmt, `(?:==|!=)\s*QMessageBox::\w+`, "")
	named := {m[1] | some m in regex.find_all_string_submatch_n(`QMessageBox::(\w+)`, call, -1); m[1] in _qt_ids}
	s := _qt_default(call, named)
}

_qt_default(_, named) := named if count(named) > 0

_qt_default(call, named) := {"Yes", "No"} if {
	count(named) == 0
	not _qt_buttons_arg(call)
	regex.match(`QMessageBox::question\s*\(`, call)
}

_qt_default(call, named) := {"Ok"} if {
	count(named) == 0
	not _qt_buttons_arg(call)
	not regex.match(`QMessageBox::question\s*\(`, call)
}

# A fourth argument that is not a QMessageBox:: constant holds the buttons
# (a variable): the set is unknown.
_qt_buttons_arg(call) if {
	m := regex.find_all_string_submatch_n(`QMessageBox::\w+\s*\((.*)$`, regex.replace(call, `"(?:[^"\\]|\\.)*"`, `""`), 1)
	count(split(m[0][1], ",")) >= 4
}

_prefix("win") := `ID`

_prefix("qt") := `QMessageBox::`

_prefix("gtk") := `GTK_RESPONSE_`

_ids("win") := _win_ids

_ids("qt") := _qt_ids

_ids("gtk") := _gtk_ids

# Buttons compared (==, != either side) on a line, optionally only against `v`.
_compared_any(kind, text) := {n |
	some m in regex.find_all_string_submatch_n(concat("", [`(?:==|!=)\s*`, _prefix(kind), `(\w+)\b|\b`, _prefix(kind), `(\w+)\s*(?:==|!=)`]), text, -1)
	n := concat("", [m[1], m[2]])
}

_compared_var(kind, text, v) := {n |
	re := concat("", [`\b`, v, `\s*(?:==|!=)\s*`, _prefix(kind), `(\w+)\b|\b`, _prefix(kind), `(\w+)\s*(?:==|!=)\s*`, v, `\b`])
	some m in regex.find_all_string_submatch_n(re, text, -1)
	n := concat("", [m[1], m[2]])
}

_cased(kind, text) := {m[1] | some m in regex.find_all_string_submatch_n(concat("", [`\bcase\s+`, _prefix(kind), `(\w+)\s*:`]), text, -1)}

# The variable a C/C++ declaration or assignment names: rc = ..., int rc = ...,
# const int answer = ..., auto reply = ..., QMessageBox::StandardButton res = ...,
# GtkWidget *dialog = ...
_var(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:const|static|auto|unsigned|signed|volatile|register)\s+)*(?:[A-Za-z_][\w:<>]*[\s*&]+)?([A-Za-z_]\w*)\s*=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
} else := ""

_another_call_between(lines, e, k) if {
	e + 1 <= k - 1
	some j in helpers.span(e + 1, k - 1)
	regex.match(_call_re, lines[j])
}

# A switch on the result: on the call line itself or on the assigned variable.
_switched(lines, i, e, v, k) if {
	regex.match(`\bswitch\s*\(`, lines[i])
}

_switched(lines, i, e, v, k) if {
	v != ""
	some j in numbers.range(e + 1, k)
	regex.match(concat("", [`\bswitch\s*\(\s*`, v, `\s*\)`]), lines[j])
}

# switch (gtk_dialog_run(GTK_DIALOG(dialog))) after the GTK dialog is built.
_switched(lines, i, e, v, k) if {
	_kind(lines[i]) == "gtk"
	some j in numbers.range(e + 1, k)
	regex.match(`\bswitch\s*\(\s*gtk_dialog_run\s*\(`, lines[j])
}

# gint response = gtk_dialog_run(...); switch (response) { ... }
_switched(lines, i, e, v, k) if {
	_kind(lines[i]) == "gtk"
	some j in numbers.range(e + 1, k)
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*gtk_dialog_run\s*\(`, lines[j], 1)
	count(m) > 0
	some j2 in numbers.range(j + 1, k)
	regex.match(concat("", [`\bswitch\s*\(\s*`, m[0][1], `\s*\)`]), lines[j2])
}

# Wrong buttons a line k tests, for the dialog called at i.
_bad(kind, lines, i, e, k, allowed, v) := (_bad_call(kind, lines, e, k, allowed) | _bad_after(kind, lines, e, k, allowed, v)) | _bad_case(kind, lines, i, e, k, allowed, v)

# A comparison inside the dialog statement itself.
_bad_call(kind, lines, e, k, allowed) := {n |
	k <= e
	some n in _compared_any(kind, lines[k])
	n in _ids(kind)
	not n in allowed
}

# A later comparison: of the assigned variable (Win32, Qt), or of any
# GTK_RESPONSE_* (gtk_dialog_run's result is usually tested inline).
_bad_after(kind, lines, e, k, allowed, v) := {n |
	k > e
	some n in _after_names(kind, lines[k], v)
	n in _ids(kind)
	not n in allowed
}

_after_names("gtk", text, _) := _compared_any("gtk", text)

_after_names(kind, text, v) := _compared_var(kind, text, v) if {
	kind != "gtk"
	v != ""
}

_after_names(kind, _, "") := set() if kind != "gtk"

_bad_case(kind, lines, i, e, k, allowed, v) := {n |
	k > i
	_switched(lines, i, e, v, k)
	some n in _cased(kind, lines[k])
	n in _ids(kind)
	not n in allowed
}

_gtk_ok(kind, lines, e, k) if kind != "gtk"

_gtk_ok("gtk", lines, e, k) if {
	not _buttons_added(lines, e, k)
}

_buttons_added(lines, e, k) if {
	some j in numbers.range(e, k)
	contains(lines[j], "_add_button")
}

# The first dialog call on the line sits inside a string literal: an odd number
# of unescaped double quotes before it.
_call_in_string(line) if {
	prefix := regex.replace(line, `(?:\bMessageBox(?:Ex)?[AW]?|\bQMessageBox::\w+|\bgtk_message_dialog_new\w*)\s*\(.*$`, "")
	quotes := count(regex.find_n(`"`, regex.replace(prefix, `\\.`, ""), -1))
	quotes % 2 == 1
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`MessageBox|gtk_message_dialog_new`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_call_re, line)
	not helpers.is_comment_line(line)
	not _call_in_string(line)
	kind := _kind(line)
	e := _stmt_end(lines, i)
	allowed := _allowed(kind, _stmt(lines, i, e))
	v := _var(line)
	some k in numbers.range(i, min([count(lines) - 1, e + 12]))
	not helpers.is_comment_line(lines[k])
	not _another_call_between(lines, e, k)
	_gtk_ok(kind, lines, e, k)
	bad := _bad(kind, lines, i, e, k, allowed, v)
	count(bad) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("The dialog's answer is compared with %v, a button this dialog does not offer: the branch the user confirms never runs (or always runs). Compare with the buttons the dialog shows", [concat(", ", sort([b | some b in bad]))]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": lines[k],
	}
}

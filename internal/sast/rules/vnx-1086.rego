# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1086

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1086",
	"name": "Class with Excessive Number of Child Classes",
	"description": "A Python class defined in the project that more than 20 classes in the project derive from directly (`class X(Base)`, `class X(Mixin, Base)`, `class X(pkg.Base)`, or a class head split over several lines). A base with that many children is a change amplifier: every edit to it, including a security fix to a method its children inherit or override, has to be checked against all of them. One finding per base class definition, with the child count. Children are counted across every non-test Python file by the last component of the base name; keyword arguments in the class head (`metaclass=...`) are ignored. Not reported: bases with 20 children or fewer, bases not defined in the project (`models.Model`, `Exception`, `object`), children of a framework class qualified by its module (`forms.Form`, `models.Model`, `db.Model`, `nn.Module`, `enum.Enum`, `serializers.*`, ...), which are not counted toward a project class of the same name, children in third-party trees and Django migrations, children declared in test files, and class heads in comments or doctests. Two unrelated classes with the same name are counted as one; the threshold is this rule's choice, as CWE-1086 does not fix one.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1086/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1086],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-child-classes", "maintainability", "cwe-1086"],
}

_max_children := 20

_class_head_re := `(?m)^[ \t]*class[ \t]+[A-Za-z_]\w*[ \t]*\(([^)]*)\)`

# Every (base name) occurrence in every non-test class head, one entry per child.
_child_bases := [b |
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	not _generated(path)
	contains(content, "class")
	some m in regex.find_all_string_submatch_n(_class_head_re, content, -1)
	some raw in split(m[1], ",")
	b := _base_name(raw)
]

# Django migrations are generated, one `class Migration(migrations.Migration)`
# per file; third-party trees are not the project's design.
_generated(path) if regex.match(`(^|/)migrations/[^/]+\.py$`, path)

_generated(path) if regex.match(`(^|/)(site-packages|dist-packages|vendor|third_party|node_modules|\.venv|venv)/`, path)

# A base qualified by a well-known framework or standard-library module
# (`forms.Form`, `models.Model`, `db.Model`, `nn.Module`, `enum.Enum`) is that
# framework's class, not a same-named class the project happens to define.
_framework_qualified := `^(?:[\w.]*\.)?(?:models|forms|serializers|generics|generic|viewsets|admin|migrations|db|nn|enum|abc|typing|unittest|ttk|tk|tkinter|QtWidgets|QtCore|QtGui|ast|json|logging|threading|collections|argparse|django|rest_framework|pydantic|sqlalchemy|marshmallow|graphene|scrapy|click|wtforms|flask_wtf)\.[A-Za-z_]\w*$`

_base_name(raw) := name if {
	t := trim_space(regex.replace(raw, `#[^\n]*`, ""))
	t != ""
	not contains(t, "=")
	regex.match(`^[A-Za-z_][\w.]*(\[.*\])?$`, t)
	bare := regex.replace(t, `\[.*\]$`, "")
	not regex.match(_framework_qualified, bare)
	parts := split(bare, ".")
	name := parts[count(parts) - 1]
}

# Run-length counts over the sorted list: O(n log n) rather than one pass of
# the whole list per distinct name.
_sorted := sort(_child_bases)

_last := count(_sorted) - 1

_run_starts := [i |
	some i in numbers.range(0, _last)
	_is_run_start(i)
]

_is_run_start(0)

_is_run_start(i) if {
	i > 0
	_sorted[i] != _sorted[i - 1]
}

_counts[name] := n if {
	count(_sorted) > _max_children
	some j, start in _run_starts
	name := _sorted[start]
	n := _run_end(j) - start
}

_run_end(j) := _run_starts[j + 1] if j + 1 < count(_run_starts)

_run_end(j) := count(_sorted) if j + 1 == count(_run_starts)

_crowded := {name | some name, n in _counts; n > _max_children}

# `class Migration(migrations.Migration)` shadows the base it names; it is a
# child, not the definition of the base.
_derives_from_same_name(line, name) if regex.match(sprintf(`^[ \t]*class[ \t]+%s[ \t]*\([^)]*\b%s\b`, [name, name]), line)

findings contains finding if {
	count(_crowded) > 0
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	startswith(trim_left(line, " \t"), "class")
	m := regex.find_all_string_submatch_n(`^[ \t]*class[ \t]+([A-Za-z_]\w*)\b`, line, 1)
	count(m) == 1
	name := m[0][1]
	name in _crowded
	not _derives_from_same_name(line, name)
	not _generated(path)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Class %s has %d direct subclasses in this project (limit %d); consider composition or splitting the hierarchy so a change to the base can be reviewed", [name, _counts[name], _max_children]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

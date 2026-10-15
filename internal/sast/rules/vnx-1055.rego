# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1055

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1055",
	"name": "Multiple Inheritance from Concrete Classes",
	"description": "A Python class inherits from two or more concrete classes defined in the same file (CWE-1055): each of those bases has its own state or behaviour (its body defines a method or assigns an attribute) and none of them is abstract, a mixin or an interface, so the subclass depends on the method resolution order to decide whose __init__, attributes and overrides win. The class header may span several lines. A base counts as abstract, and is ignored, when its name ends in Mixin, Base, ABC, Interface or Protocol, it derives from ABC/ABCMeta/Protocol/a Mixin, or its body uses @abstractmethod, raises NotImplementedError or declares a Django abstract model (class Meta: abstract = True). Not reported: a single concrete base combined with mixins or ABCs, bases imported from other modules (the rule cannot see whether they are concrete), empty marker classes (exception tag hierarchies such as class ConnectTimeout(ConnectionError, Timeout) whose bases only pass), Generic[...]/metaclass= arguments, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1055/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1055],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["multiple-inheritance", "design", "cwe-1055"],
}

_class_re := `^(\s*)class\s+([A-Za-z_]\w*)\s*(\(|:)`

_indent(line) := count(line) - count(trim_left(line, " \t"))

# The header text from `class` to the closing parenthesis, across up to six
# lines.
_header(lines, i) := h if {
	last := min([count(lines) - 1, i + 6])
	h := concat(" ", [lines[k] | some k in numbers.range(i, last)])
}

_bases(lines, i) := bs if {
	m := regex.find_all_string_submatch_n(`^\s*class\s+[A-Za-z_]\w*\s*\(([^)]*)\)`, _header(lines, i), 1)
	count(m) > 0
	raw := regex.replace(m[0][1], `\[[^\]]*\]`, "")
	bs := [b |
		some part in split(raw, ",")
		b := trim_space(part)
		b != ""
		not contains(b, "=")
	]
}

# Last line of the class body (bounded to 300 lines).
_body_end(lines, i) := e if {
	k := _indent(lines[i])
	last := min([count(lines) - 1, i + 300])
	outs := [j |
		some j in numbers.range(i + 1, last)
		trim_space(lines[j]) != ""
		not helpers.is_comment_line(lines[j])
		_indent(lines[j]) <= k
	]
	e := _end_of(outs, last)
}

_end_of(outs, _) := outs[0] - 1 if count(outs) > 0

_end_of(outs, last) := last if count(outs) == 0

_body(lines, i) := concat("\n", [lines[k] | e := _body_end(lines, i); e > i; some k in numbers.range(i + 1, e)])

_abstract_name(name) if regex.match(`(?:Mixin|Base|ABC|Interface|Protocol)$`, name)

_abstract_name(name) if startswith(name, "Abstract")

_abstract_def(lines, i, _) if {
	some b in _bases(lines, i)
	regex.match(`(?:^|\.)(?:ABC|ABCMeta|Protocol|\w*Mixin|Generic|TypedDict|NamedTuple|Enum|IntEnum|StrEnum)$`, b)
}

_abstract_def(lines, i, _) if regex.match(`metaclass\s*=\s*(?:abc\.)?ABCMeta`, _header(lines, i))

# Django abstract models: class Meta: abstract = True.
_abstract_def(_, _, body) if regex.match(`(?m)^\s+abstract\s*=\s*True\b`, body)

_abstract_def(_, _, body) if regex.match(`@(?:abc\.)?abstract(?:method|property|classmethod|staticmethod)|raise\s+NotImplementedError`, body)

# The body defines behaviour or state: a method or an attribute assignment.
_has_state(body) if regex.match(`(?m)^\s+(?:async\s+)?def\s|^\s+[A-Za-z_]\w*\s*(?::[^=]+)?=[^=]`, body)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*class\s+\w+\s*\([^)]*,`, content)
	lines := split(content, "\n")
	classes := [[name, i] |
		some i, line in lines
		contains(line, "class ")
		m := regex.find_all_string_submatch_n(_class_re, line, 1)
		count(m) > 0
		name := m[0][2]
	]
	defs := {name: idxs |
		some c in classes
		name := c[0]
		idxs := [p[1] | some p in classes; p[0] == name]
	}
	concrete := {name |
		some name, idxs in defs
		not _abstract_name(name)
		every k in idxs {
			not _abstract_def(lines, k, _body(lines, k))
		}
		some k in idxs
		_has_state(_body(lines, k))
	}
	count(concrete) >= 2
	some c in classes
	i := c[1]
	line := lines[i]
	bases := _bases(lines, i)
	hits := [b | some b in bases; b in concrete]
	count({b | some b in hits}) >= 2
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Class inherits from several concrete classes (%s); prefer composition or a single concrete base with mixins (CWE-1055)", [concat(", ", hits)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

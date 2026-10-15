# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_594

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-594",
	"name": "Persisted or session-scoped Java class that is not Serializable",
	"description": "A Java class that the container may write to disk or move between nodes is declared without implementing Serializable: a JPA @Entity, @Embeddable or @MappedSuperclass (javax or jakarta), or a CDI @SessionScoped or @ConversationScoped bean, whose declaration (which may span lines, or follow the annotation on the same line) neither implements Serializable or Externalizable nor extends another class. When the container passivates the session, replicates it across a cluster or detaches the entity for a remote call, serialisation fails or the state is silently lost. Reported on the class declaration. Not reported: classes that implement Serializable or Externalizable (or a Spring Security interface that extends it: UserDetails, GrantedAuthority, Authentication), classes that extend a superclass (which may be Serializable; superclasses are not resolved), interfaces, records and enums, other annotations that start with Entity (@EntityListeners), and annotations in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-594/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [594],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["java", "jpa", "cdi", "serialization", "cwe-594"],
}

_anno_re := `^\s*@(?:(?:javax|jakarta)\.(?:persistence|enterprise\.context)\.)?(?:Entity|Embeddable|MappedSuperclass|SessionScoped|ConversationScoped)\b\s*(?:\(|$|@|(?:public|protected|abstract|final|class)\b)`

_class_re := `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|abstract|final|static|sealed|non-sealed)\s+)*class\s+[A-Za-z_]\w*`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?m)^\s*@(?:[\w.]*\.)?(?:Entity|Embeddable|MappedSuperclass|SessionScoped|ConversationScoped)\b`, content)
	lines := split(content, "\n")
	some j, aline in lines
	contains(aline, "@")
	regex.match(_anno_re, aline)
	i := _decl(lines, j)
	header := _header(lines, i)
	not regex.match(`\b(?:extends|\w*Serializable|Externalizable|UserDetails|GrantedAuthority|Authentication)\b`, header)
	finding := {
		"rule_id": metadata.id,
		"message": "This persisted or session-scoped class does not implement java.io.Serializable; the container cannot passivate, replicate or detach it. Implement Serializable (and declare serialVersionUID)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

# The first type declaration after the annotation, reached through further
# annotations only (no statement or other declaration in between).
_decl(lines, j) := i if {
	end := min([count(lines) - 1, j + 8])
	cands := [k |
		some k in numbers.range(j, end)
		not helpers.is_comment_line(lines[k])
		regex.match(`\b(?:class|interface|enum|record)\b|;`, lines[k])
	]
	count(cands) > 0
	i := cands[0]
	regex.match(_class_re, lines[i])
}

# The declaration up to its opening brace (at most four lines).
_header(lines, i) := h if {
	end := min([count(lines) - 1, i + 3])
	ks := [k | some k in numbers.range(i, end); contains(lines[k], "{")]
	last := min(array.concat([end], ks))
	h := concat(" ", [lines[k] | some k in numbers.range(i, last)])
}

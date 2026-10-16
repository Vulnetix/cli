# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_820

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-820",
	"name": "Missing Synchronization",
	"description": "A Java object that one instance serves every request thread (a class extending HttpServlet/GenericServlet/HttpFilter, a servlet filter extending OncePerRequestFilter/GenericFilterBean or implementing javax/jakarta Filter, a Servlet or HandlerInterceptor implementation, or a Spring @RestController/@Controller/@Service/@Component/@Repository singleton) keeps mutable state in a field and a request-handling method writes it with no synchronization: an assignment, compound assignment or ++/-- of a non-final, non-volatile field, or a mutating call (put, add, remove, clear, merge, compute*, append...) on a field holding a HashMap, ArrayList, HashSet, LinkedList, TreeMap, LinkedHashMap, ArrayDeque or StringBuilder, declared with that type or declared final as a Map/List/Set and given one in a constructor. Concurrent requests then race on it (lost updates, corrupted collections, one user's data shown to another). Not reported: writes inside a synchronized method or synchronized block, writes while an explicit Lock taken in the method (lock()/writeLock().lock()) is still held, Atomic*, Concurrent*, CopyOnWrite*, ThreadLocal, Collections.synchronized* and volatile fields, injected fields (@Autowired/@Inject/@Value/@Resource), writes in constructors, static initialisers, init()/afterPropertiesSet()/@PostConstruct methods and setters, locals and parameters that shadow the field, classes that are not shared (entities, DTOs), beans scoped prototype/request/session, test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-820/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [820],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["missing-sync", "cwe-820", "concurrency", "race-condition"],
}

_shared_re := `extends\s+(?:HttpServlet|GenericServlet|HttpFilter|OncePerRequestFilter|GenericFilterBean|HandlerInterceptorAdapter)\b|implements\s+(?:[\w.<>]+\s*,\s*)*(?:(?:javax|jakarta)\.servlet\.)?(?:Filter|Servlet|HandlerInterceptor)\b|@(?:RestController|Controller|Service|Component|Repository)\b`

_scoped_re := `@Scope\s*\(\s*(?:value\s*=\s*|scopeName\s*=\s*)?(?:"(?:prototype|request|session)"|\w+\.SCOPE_(?:PROTOTYPE|REQUEST|SESSION))|@(?:RequestScope|SessionScope)\b`

_field_re := `^\s*((?:(?:private|protected|public|static|transient|final)\s+)*)([\w.]+(?:<[^;=]*>)?(?:\[\])*)\s+([A-Za-z_]\w*)\s*(=\s*[^;]*)?;\s*$`

_safe_type := `Atomic|Concurrent|CopyOnWrite|ThreadLocal|LongAdder|DoubleAdder|Logger|Log\b|synchronized|Lock\b|Semaphore|Collections\.unmodifiable|List\.of|Map\.of|Set\.of`

_collection := `\b(?:HashMap|ArrayList|HashSet|LinkedList|TreeMap|LinkedHashMap|TreeSet|LinkedHashSet|ArrayDeque|PriorityQueue|StringBuilder|IdentityHashMap|WeakHashMap|EnumMap)\b`

_mutators := `(?:put|putAll|putIfAbsent|add|addAll|addFirst|addLast|remove|removeIf|removeAll|clear|set|computeIfAbsent|computeIfPresent|compute|merge|append|insert|offer|poll|push|pop|sort|replaceAll|retainAll|setLength)`

_injected := `@(?:Autowired|Inject|Value|Resource|PersistenceContext|PersistenceUnit)\b`

_lifecycle := {"init", "initialize", "afterPropertiesSet", "destroy", "setUp", "configure", "postConstruct", "setServletConfig"}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_member_indent(lines) := min(array.concat([4], [_indent(l) |
	some l in lines
	regex.match(`^\s+(?:public|private|protected)\s`, l)
]))

# [name, kind] of each mutable member field.
_fields(lines, mi, content) := {[n, kind] |
	some j, l in lines
	_indent(l) == mi
	contains(l, ";")
	not regex.match(`^[^=]*\(`, l)
	not contains(l, "volatile")
	m := regex.find_all_string_submatch_n(_field_re, l, 1)
	count(m) > 0
	not regex.match(_safe_type, l)
	not _injected_at(lines, j)
	n := m[0][3]
	kind := _kind_of(m[0][1], l, n, content)
}

_kind(mods, l) := "collection" if regex.match(_collection, l)

_kind(mods, l) := "scalar" if {
	not regex.match(_collection, l)
	not contains(mods, "final")
}

_injected_at(lines, j) if regex.match(_injected, lines[j])

_injected_at(lines, j) if {
	j > 0
	regex.match(_injected, lines[j - 1])
}

_write_re(n, "scalar") := concat("", [`(?:^|[^\w.])(?:this\.)?`, n, `\s*(?:\+\+|--|[+\-*/%|&^]?=[^=])|(?:\+\+|--)\s*(?:this\.)?`, n, `\b`])

_write_re(n, "collection") := concat("", [`(?:^|[^\w.])(?:this\.)?`, n, `\.`, _mutators, `\s*\(`])

# The member declaration enclosing line i: the nearest code line above at the
# member indent.
_member(lines, i, mi) := j if {
	cands := [k |
		some k in numbers.range(max([0, i - 150]), i - 1)
		l := lines[k]
		_indent(l) == mi
		t := trim_space(l)
		t != ""
		not startswith(t, "}")
		not startswith(t, "@")
		not helpers.is_comment_line(l)
	]
	count(cands) > 0
	j := max(cands)
}

_method_name(decl) := n if {
	not regex.match(`^\s*(?:return|new|if|for|while|switch|static\s*\{|\{)`, decl)
	m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*\(`, decl, 1)
	n := m[0][1]
}

_class_name(content) := n if {
	m := regex.find_all_string_submatch_n(`\bclass\s+([A-Za-z_]\w*)`, content, 1)
	n := m[0][1]
}

_excluded_method(_, decl, _, _, _) if contains(decl, "synchronized")

_excluded_method(name, _, _, _, _) if _lifecycle[name]

_excluded_method(name, _, _, _, _) if regex.match(`^set[A-Z]`, name)

_excluded_method(name, _, _, _, content) if name == _class_name(content)

_excluded_method(_, _, lines, j, _) if {
	some k in numbers.range(max([0, j - 3]), j - 1)
	regex.match(`@(?:PostConstruct|PreDestroy|Bean|BeforeEach|BeforeAll|Before|Autowired)\b`, lines[k])
}

# A local or parameter of the same name shadows the field (only for writes
# that do not say this.).
_shadowed(lines, j, i, n, line) if {
	not regex.match(concat("", [`\bthis\.`, n, `\b`]), line)
	re := concat("", [`\b`, n, `\b`])
	some k in numbers.range(j, max([j, i - 1]))
	k == j
	regex.match(re, lines[k])
}

_shadowed(lines, j, i, n, line) if {
	not regex.match(concat("", [`\bthis\.`, n, `\b`]), line)
	re := concat("", [`(?:^|[\s(,])(?:final\s+)?[\w.]+(?:<[^>]*>)?(?:\[\])*\s+`, n, `\s*[=;:,)]`])
	j + 1 <= i
	some k in numbers.range(j + 1, i)
	regex.match(re, lines[k])
}

# A synchronized block opened in the method still encloses line i.
_in_sync_block(lines, j, i) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	regex.match(`^\s*synchronized\s*\(`, lines[k])
	ik := _indent(lines[k])
	_indent(lines[i]) > ik
	not _closed(lines, k, i, ik)
}

_closed(lines, k, i, ik) if {
	k + 1 <= i - 1
	some m in helpers.span(k + 1, i - 1)
	_indent(lines[m]) <= ik
	startswith(trim_space(lines[m]), "}")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_shared_re, content)
	not regex.match(_scoped_re, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	mi := _member_indent(lines)
	fields := _fields(lines, mi, content)
	count(fields) > 0
	some f in fields
	n := f[0]
	re := _write_re(n, f[1])
	some i, line in lines
	contains(line, n)
	_indent(line) > mi
	regex.match(re, line)
	not helpers.is_comment_line(line)
	j := _member(lines, i, mi)
	decl := lines[j]
	name := _method_name(decl)
	not _excluded_method(name, decl, lines, j, content)
	not _shadowed(lines, j, i, n, line)
	not _in_sync_block(lines, j, i)
	not _in_lock(lines, j, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Field '%s' of a shared servlet/singleton bean is modified by '%s' without synchronization; concurrent requests race on it. Keep per-request state in locals, or use a synchronized block, an Atomic*/Concurrent* type or a request-scoped bean", [n, name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_kind_of(mods, l, _, _) := k if k := _kind(mods, l)

# A field declared by interface (Map, List, Set...) and given a non-thread-safe
# implementation in a constructor or initialiser.
_kind_of(mods, l, n, content) := "collection" if {
	not regex.match(_collection, l)
	contains(mods, "final")
	regex.match(`\b(?:Map|List|Set|Collection|Deque|Queue|SortedMap|NavigableMap|SortedSet)\s*<`, l)
	regex.match(concat("", [`(?:^|[^\w.])(?:this\.)?`, n, `\s*=\s*new\s+`, _collection]), content)
}

# An explicit java.util.concurrent lock taken in the method and not yet
# released at line i.
_in_lock(lines, j, i) if {
	j + 1 <= i - 1
	some k in helpers.span(j + 1, i - 1)
	regex.match(`\.\s*(?:lock|lockInterruptibly|tryLock)\s*\([^)]*\)|\.\s*(?:writeLock|readLock)\s*\(\s*\)\s*\.\s*lock\s*\(`, lines[k])
	not _unlocked(lines, k, i)
}

_unlocked(lines, k, i) if {
	some m in helpers.span(k + 1, i - 1)
	regex.match(`\.\s*unlock\s*\(`, lines[m])
}

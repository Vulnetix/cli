package vulnetix.rules.vnx_java_028

import rego.v1

import data.vulnetix.helpers

metadata := {
    "id": "VNX-JAVA-028",
    "name": "SQL injection via StringBuilder-assembled SQL in Java",
    "description": "A JDBC or Spring JdbcTemplate call (Statement execute/executeQuery/executeUpdate/executeLargeUpdate/addBatch, Connection prepareStatement/prepareCall, JdbcTemplate query/queryForList/queryForObject/queryForMap/queryForRowSet/update/batchUpdate, Android SQLiteDatabase rawQuery/execSQL) receives SQL text assembled in a StringBuilder or StringBuffer, where an append() call adds a non-constant value: sb.append(name), sb.append(\" AND x = '\" + name + \"'\"), or a chained new StringBuilder(\"SELECT ...\").append(id).toString() inline in the call. The builder is read from its nearest plain assignment up to 40 lines above the call (chained and multi-line appends included), and a SQL string literal must appear in what it is built from. The enclosing method (at most 120 lines up) is read before reporting: an operand that provably holds a constant at the call is not run-time data, namely a literal or constant expression it was last assigned on every path, the taken side of an if/else or ternary whose condition folds to a constant, the selected case of a switch on a constant, the element a list index or map key actually holds when that is a literal, and the result of a method in the same file whose every return is constant. A call into code the analysis cannot see is read as inert, and its value is constant, when it is not named like a source (read*, next*, getParameter*, getHeader*, getCookie*, getenv, getProperty, query, execute), every argument is a constant, and its receiver is a type name, a new expression with constant arguments, or a local built from such a call that is only ever called with constant arguments; a call handed a run-time argument, made on a run-time receiver or named like a source stays reported. Not reported: SQL built into a String by concatenation, +=, String.format(), concat() or .formatted() (inline or through a variable), which is reported by VNX-JAVA-003; builders that append only literals and UPPER_CASE constants; parameterised queries; builders holding no SQL; the pattern inside a string literal or a comment. The rule follows values only within the enclosing method and does not judge whether the appended value is attacker-controlled.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-028/",
    "languages": ["java"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [89],
    "capec": ["CAPEC-66"],
    "attack_technique": ["T1059.003"],
    "cvssv4": "",
    "cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
    "tags": ["sql-injection", "database", "query"],
}

_sink_names := `executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|query|queryForList|queryForObject|queryForMap|queryForRowSet|queryForLong|queryForInt|queryForStream|update|batchUpdate|rawQuery|execSQL`

_sink_re := concat("", [`\.(?:`, _sink_names, `)\s*\(`])

_sink_arg_re := concat("", [`\.(?:`, _sink_names, `)\s*\(([^;]*)`])

_str_re := `"(?:[^"\\\n]|\\.)*"`

# A string literal that carries SQL.
_sql_lit_re := `(?i)"[^"]*(?:\b(?:select\s|insert\s+into|update\s+\w+\s+set|delete\s+from|merge\s+into|(?:create|drop)\s+(?:table|schema|user|index|view|database)|alter\s+table|truncate\s|from\s|where\s|values\s*\(|order\s+by|group\s+by|set\s+schema)|\{\s*call\b)`

_file_gate := `(?i)"[^"\n]*\b(select|insert|update|delete|create|drop|alter|truncate|merge|call|schema|from|where|values)\b|"""`

_is_const(name) if {
    parts := split(name, ".")
    regex.match(`^[A-Z][A-Z0-9_]*$`, parts[count(parts) - 1])
}

# An operand of a concatenation, a format, a concat() or an append() that is
# not a literal and not an UPPER_CASE constant.
_dynamic_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`\+\s*([A-Za-z_][\w.]*)`, stripped, -1)
    not _is_const(m[1])
}

_dynamic_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*)(?:\([^()]*\))?\s*\+[^=]`, stripped, -1)
    not _is_const(m[1])
    not regex.match(`^(String|return|new)$`, m[1])
}

_dynamic_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`\.(?:concat|append|formatted)\(\s*([A-Za-z_][\w.]*)`, stripped, -1)
    not _is_const(m[1])
}

_dynamic_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`String\.format\(\s*""\s*,([^;]*)`, stripped, -1)
    some a in regex.find_n(`[A-Za-z_][\w.]*`, m[1], -1)
    not _is_const(a)
}

_strip(text) := regex.replace(text, _str_re, `""`)

# The statement starting at line i (up to 8 lines, cut at the first ';').
_stmt(lines, i) := s if {
    joined := concat(" ", array.slice(lines, i, min([count(lines), i + 8])))
    s := regex.find_n(`^[^;]*`, joined, 1)[0]
}

# All the statements in the 40 lines above i that build variable v.
# The nearest plain assignment `v = ...` above i (not `v += ...` or
# `v = v + ...`): statements before it built an earlier value of v.
_last_assign(lines, i, v) := max(ks) if {
    ks := [k |
        some k in numbers.range(max([0, i - 40]), i - 1)
        l := lines[k]
        contains(l, v)
        regex.match(concat("", [`(?:^|[^\w.])`, v, `\s*=(?:[^=]|$)`]), l)
        not regex.match(concat("", [`(?:^|[^\w.])`, v, `\s*=\s*`, v, `\b`]), l)
        not helpers.is_comment_line(l)
    ]
    count(ks) > 0
}

_from(lines, i, v) := k if {
    k := _last_assign(lines, i, v)
} else := max([0, i - 40])

# The statements that build v: its nearest plain assignment and every
# `v = ...`, `v += ...` and `v.append(...)` after it.
_build_stmts(lines, i, v) := [s |
    some k in numbers.range(_from(lines, i, v), i - 1)
    l := lines[k]
    contains(l, v)
    not helpers.is_comment_line(l)
    regex.match(concat("", [`(?:^|[^\w.])`, v, `\s*(?:\+?=(?:[^=]|$)|\.append\()`]), l)
    s := _stmt(lines, k)
]

_lambda(arg) if regex.match(`^\s*\(?[\w\s,]*\)?\s*->`, arg)

# A StringBuilder/StringBuffer append() whose argument is not a literal or an
# UPPER_CASE constant: append(name), append(" AND x = '" + name + "'").
_append_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`\.append\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)`, stripped, -1)
    not regex.match(`^[^?"]*\?\s*""\s*:\s*""\s*$`, m[1])
    _dynamic_operand(concat("", ["+ ", m[1]]))
}

# The SQL is assembled with append(): concatenation, String.format(),
# concat() and formatted() into a String are VNX-JAVA-003's to report, which
# does not follow a builder's append() calls.
_append_built(text, stmts) if {
    regex.match(_sql_lit_re, text)
    some s in stmts
    contains(s, ".append(")
    _append_operand(_strip(s))
}

# inline: the SQL is built in the call's own argument
_vulnerable(_, _, arg) if {
    not _lambda(arg)
    _append_built(arg, [arg])
}

# the argument is a builder variable (or its toString()) built above
_vulnerable(lines, i, arg) if {
    m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:\.toString\(\)\s*)?(?:[,)]|$)`, arg, 1)
    count(m) > 0
    v := m[0][1]
    not _is_const(v)
    stmts := _build_stmts(lines, i, v)
    _append_built(concat("\n", stmts), stmts)
}

findings contains finding if {
    some path, content in input.file_contents
    endswith(path, ".java")
    regex.match(_file_gate, content)
    regex.match(concat("", ["(?m)", _sink_re]), content)
    lines := split(content, "\n")
    some i, line in lines
    regex.match(_sink_re, line)
    not helpers.is_comment_line(line)
    regex.match(_sink_re, _strip(line))
    m := regex.find_all_string_submatch_n(_sink_arg_re, _stmt(lines, i), 1)
    count(m) > 0
    _vulnerable(lines, i, m[0][1])
    _vulnerable_live(lines, i, m[0][1], helpers.flow_consts(lines, i))
    finding := {
        "rule_id": metadata.id,
        "message": "SQL assembled in a StringBuilder from a non-constant append() reaches a JDBC/JdbcTemplate call; append ? placeholders instead and bind the values on a PreparedStatement or JdbcTemplate",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}

# ── In-method flow ───────────────────────────────────────────────────────
# The same two checks after reading the method: an operand that provably
# holds a constant at the call (a literal, the taken side of a constant
# condition or switch, a constant list index or map key, a same-file method
# returning a constant) is not run-time data.

_vulnerable_live(lines, i, arg, consts) if {
    not _lambda(arg)
    folded := helpers.flow_fold(arg, i, consts)
    _append_built(folded, [folded])
}

_vulnerable_live(lines, i, arg, consts) if {
    m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:\.toString\(\)\s*)?(?:[,)]|$)`, arg, 1)
    count(m) > 0
    v := m[0][1]
    not _is_const(v)
    not consts[v]
    stmts := [s |
        some k in numbers.range(_from(lines, i, v), i - 1)
        l := lines[k]
        contains(l, v)
        not helpers.is_comment_line(l)
        regex.match(concat("", [`(?:^|[^\w.])`, v, `\s*(?:\+?=(?:[^=]|$)|\.append\()`]), l)
        s := helpers.flow_fold(_stmt(lines, k), k, consts)
    ]
    _append_built(concat("\n", stmts), stmts)
}

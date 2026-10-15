package vulnetix.rules.vnx_go_022

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-022",
	"name": "Use of eval() or dynamic code execution",
	"description": "Code supplied from outside the program is handed to an embedded interpreter, expression engine or template parser. Reported sinks, each only in a file importing its package: goja vm.RunString / RunScript / goja.Compile / goja.Parse, otto vm.Run / vm.Eval, yaegi i.Eval, gopher-lua L.DoString, govaluate NewEvaluableExpression, expr-lang expr.Compile / expr.Eval, gval.Evaluate, cel-go env.Compile / env.Parse, tengo NewScript, starlark ExecFile / Eval, and html/template or text/template template.New(...).Parse, also with .Funcs/.Delims/.Option chained before Parse (server-side template injection). The code argument must be an HTTP request value (r.FormValue, r.URL.Query().Get, gin/echo c.Query/c.PostForm), the request body (io.ReadAll(r.Body), a struct decoded from it, c.GetRawData), a variable assigned from one of those (one further assignment is followed), or a string parameter of the enclosing function passed straight through (a helper that runs whatever its caller passes). Not reported: fields of a parameter (rule.When: the caller loaded it, usually from configuration), scripts and expressions that are string literals, constants, embedded files or package variables, expressions read from configuration files or loop variables over configured rules, the compiled program passed to expr.Run, calls on the program's own types named Eval or Run in files importing no interpreter, the word eval( in strings and names, comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-022/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-64"],
	"attack_technique": ["T1059.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["rce", "eval", "dynamic-code-execution"],
}

_lit_re := "\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`|'(?:[^'\\\\\\n]|\\\\.)+'"

_strip(s) := regex.replace(s, _lit_re, `""`)

# [call regex on literal-stripped code, index of the code argument, import
# marker, whether the receiver is generic and must not be another package]
_sinks := [
	[`\.RunString\(`, 0, `"github.com/dop251/goja"`, false],
	[`\.RunScript\(`, 1, `"github.com/dop251/goja"`, false],
	[`\bgoja\.(?:Compile|Parse)\(`, 1, `"github.com/dop251/goja"`, false],
	[`(?:^|[^\w.])(?:[a-z]\w*)\.Run\(`, 0, `"github.com/robertkrimen/otto"`, true],
	[`\.Eval\(`, 0, `"github.com/robertkrimen/otto"`, true],
	[`\.Eval\(`, 0, `"github.com/traefik/yaegi/interp"`, false],
	[`\.DoString\(`, 0, `"github.com/yuin/gopher-lua"`, false],
	[`\bgovaluate\.NewEvaluableExpression(?:WithFunctions)?\(`, 0, `"github.com/Knetic/govaluate"`, false],
	[`\bexpr\.(?:Compile|Eval)\(`, 0, `/expr"`, false],
	[`\bgval\.Evaluate\(`, 0, `"github.com/PaesslerAG/gval"`, false],
	[`\b[a-z]\w*\.(?:Compile|Parse)\(`, 0, `"github.com/google/cel-go/cel"`, true],
	[`\btengo\.NewScript\(`, 0, `"github.com/d5/tengo`, false],
	[`\bstarlark\.(?:ExecFile|Eval)\(`, 2, `"go.starlark.net/starlark"`, false],
	[`\btemplate\.New\([^()]*\)(?:\.(?:Funcs|Delims|Option)\([^()]*\))*\.Parse\(`, 0, `/template"`, false],
]

# Receivers that are other packages' Compile/Parse/Run, not an interpreter.
_not_interp_recv := `\b(?:expr|goja|regexp|template|json|yaml|url|time|strconv|filepath|path|flag|cmd|exec|errgroup|g|wg|suite|t|b|m)\.(?:Compile|Parse|Run)\($`

_source_re := `\b(?:r|req|request|(?:c|ctx)\.Request)\.(?:(?:FormValue|PostFormValue|PathValue|Form\.Get|PostForm\.Get|Header\.Get|Body)\b|URL\.Query\(\))|\b(?:c|ctx)\.(?:Query|DefaultQuery|PostForm|DefaultPostForm|Param|FormValue|QueryParam|GetHeader|GetRawData|Body)\(|\bmux\.Vars\(|\bchi\.URLParam\(|\.ByName\(`

_balanced(pre) if {
	strings.count(pre, "(") == strings.count(pre, ")")
	strings.count(pre, "[") == strings.count(pre, "]")
	strings.count(pre, "{") == strings.count(pre, "}")
}

_split_top(s, sep) := pieces if {
	cuts := [p | some p in indexof_n(s, sep); _balanced(substring(s, 0, p))]
	bounds := array.concat(array.concat([-1], cuts), [count(s)])
	pieces := [trim_space(substring(s, bounds[k] + 1, (bounds[k + 1] - bounds[k]) - 1)) |
		some k in numbers.range(0, count(bounds) - 2)
	]
}

_inside(rest) := substring(rest, 0, min(closes)) if {
	closes := [p | some p in indexof_n(rest, ")"); _balanced(substring(rest, 0, p))]
	count(closes) > 0
}

# string(x), []byte(x), x, x.Field -> x
_root(arg) := v if {
	m := regex.find_all_string_submatch_n(`^(?:string\(|\[\]byte\()?\s*\*?([A-Za-z_]\w*)(?:\.[A-Za-z_]\w*)*\s*\)?$`, arg, 1)
	count(m) > 0
	v := m[0][1]
	not v in {"nil", "true", "false"}
}

_fn_start(lines, i) := max(array.concat([max([0, i - 150])], [j |
	some j in numbers.range(max([0, i - 150]), i)
	startswith(lines[j], "func ")
]))

_params(lines, i) := ps if {
	sigs := [j |
		some j in numbers.range(max([0, i - 150]), i)
		contains(lines[j], "func")
		regex.match(`\bfunc\b\s*(?:\([^)]*\)\s*)?\w*\s*\(`, lines[j])
	]
	count(sigs) > 0
	sig := _strip(lines[max(sigs)])
	m := regex.find_all_string_submatch_n(`\bfunc\b\s*(?:\([^)]*\)\s*)?\w*\s*\(([^)]*)\)`, sig, -1)
	count(m) > 0
	ps := {n |
		some piece in split(m[count(m) - 1][1], ",")
		words := regex.split(`\s+`, trim_space(piece))
		n := words[0]
		n != ""
	}
}

# Variables of the function assigned from request data, or decoded from it.
_tainted(lines, fs, i) := t if {
	direct := {v |
		some j in numbers.range(fs, i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		regex.match(_source_re, _strip(l))
		some v in _assigned(l)
	}
	hop := {v |
		some j in numbers.range(fs, i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		some w in direct
		regex.match(concat("", [`\b`, w, `\b`]), _rhs(l))
		some v in _assigned(l)
	}
	t := direct | hop
}

_tainted(_, fs, i) := set() if i <= fs

# name := ..., name, err := ..., and Decode(&name) / Bind(&name)
_assigned(l) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+)?([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)*(?::=|=)[^=]`, l, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
} | {v |
	some m in regex.find_all_string_submatch_n(`(?:Decode|Unmarshal|Bind\w*)\((?:[^&()]*,\s*)?&([A-Za-z_]\w*)\)`, l, -1)
	v := m[1]
}

_rhs(l) := r if {
	m := regex.find_all_string_submatch_n(`(?::=|=)(.*)$`, l, 1)
	count(m) > 0
	r := m[0][1]
}

_rhs(l) := "" if not regex.match(`(?::=|=)`, l)

_bad_arg(arg, _, _, _) if regex.match(_source_re, arg)

# A string parameter passed straight through (code, string(code)). A field of
# a parameter (rule.When) is a value the caller loaded, often from
# configuration, and is not followed.
_bad_arg(arg, lines, i, _) if {
	m := regex.find_all_string_submatch_n(`^(?:string\(|\[\]byte\()?\s*\*?([A-Za-z_]\w*)\s*\)?$`, arg, 1)
	count(m) > 0
	v := m[0][1]
	v in _params(lines, i)
}

_bad_arg(arg, lines, i, fs) if {
	v := _root(arg)
	v in _tainted(lines, fs, i)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	regex.match(`"(?:github\.com/(?:dop251/goja|robertkrimen/otto|traefik/yaegi|yuin/gopher-lua|Knetic/govaluate|antonmedv/expr|expr-lang/expr|PaesslerAG/gval|google/cel-go|d5/tengo)|go\.starlark\.net|(?:html|text)/template)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:Run|RunString|RunScript|Eval|DoString|Compile|Parse|NewScript|ExecFile|Evaluate|NewEvaluableExpression\w*)\(`, line)
	not helpers.is_comment_line(line)
	code := _strip(concat("\n", array.slice(lines, i, i + 4)))
	first := _strip(line)
	some sink in _sinks
	contains(content, sink[2])
	pm := regex.find_all_string_submatch_n(concat("", [`^[\s\S]*?`, sink[0]]), first, 1)
	count(pm) > 0
	_recv_ok(sink[3], pm[0][0])
	call := _inside(substring(code, count(pm[0][0]), -1))
	args := _split_top(call, ",")
	sink[1] < count(args)
	_bad_arg(args[sink[1]], lines, i, _fn_start(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "Request data or a caller-supplied string is evaluated by an embedded interpreter, expression engine or template parser; never execute code or templates a user can write",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_recv_ok(false, _)

_recv_ok(true, prefix) if not regex.match(_not_interp_recv, prefix)

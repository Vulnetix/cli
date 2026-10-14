package vulnetix.rules.vnx_go_019

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-019",
	"name": "Go debug endpoints (pprof, expvar) served on all interfaces",
	"description": "Go profiling and runtime-introspection handlers are served on a listener bound to every interface (\":6060\", \"0.0.0.0:8080\", \"[::]:N\"). Reported: http.ListenAndServe/ListenAndServeTLS, an http.Server{Addr: ...} literal, or a net.Listen whose listener is passed to http.Serve, when the handler is the default mux (nil, http.DefaultServeMux, or a Server literal with no Handler) and a non-test file of the project imports net/http/pprof or expvar (whose init registers /debug/pprof/ and /debug/vars on the default mux); the same listeners when the handler is a mux the file registers pprof or expvar handlers on (mux.HandleFunc(\"/debug/pprof/\", pprof.Index), expvar.Handler()); and a gin engine passed to gin-contrib pprof.Register that is started with r.Run() or r.Run(\":N\"). These endpoints expose heap and goroutine dumps, the command line and memstats, and let a caller run CPU profiles. Not reported: a loopback address (localhost, 127.0.0.1, [::1]), an address held in a variable or read from configuration, port 0, a public listener whose handler is a mux without debug handlers (binding a service to every interface on its own is VNX-1327's concern), string literals, comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-019/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1046"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["network", "binding", "go", "pprof", "debug"],
}

# An address literal that binds every interface on a fixed, non-zero port.
_wild := `"(?:0\.0\.0\.0|\[::\])?:(?:[1-9]\d*)"`

# A non-test Go file imports net/http/pprof or expvar, whose init functions
# register their handlers on http.DefaultServeMux.
_debug_on_default_mux if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`(?m)^\s*(?:import\s+)?(?:[_\w]+\s+)?"(?:net/http/pprof|expvar)"`, content)
	not helpers.is_test_path(path)
}

_default_handler(h) if h in {"nil", "http.DefaultServeMux"}

# Muxes this file mounts profiling handlers on.
_debug_muxes(lines) := {m |
	some l in lines
	contains(l, "Handle")
	not helpers.is_comment_line(l)
	r := regex.find_all_string_submatch_n(`\b(\w+)\.Handle(?:Func)?\(\s*(?:"/debug/(?:pprof|vars)[^"]*"|[^,]+,\s*(?:pprof\.\w+|expvar\.Handler\(\)))`, l, 1)
	count(r) > 0
	m := r[0][1]
}

_debug_handler(h, _) if {
	_default_handler(h)
	_debug_on_default_mux
}

_debug_handler(h, muxes) if h in muxes

_msg := "Profiling/introspection handlers (net/http/pprof, expvar) are served on every interface; bind the debug listener to 127.0.0.1 or serve it behind authentication"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_go_file(path, content) if {
	endswith(path, ".go")
	not helpers.is_test_path(path)
	regex.match(`ListenAndServe|net\.Listen|\.Run\(`, content)
}

# http.ListenAndServe(":6060", handler) / ListenAndServeTLS(addr, cert, key, handler)
findings contains finding if {
	some path, content in input.file_contents
	_go_file(path, content)
	contains(content, "ListenAndServe")
	lines := split(content, "\n")
	muxes := _debug_muxes(lines)
	some i, line in lines
	contains(line, "http.ListenAndServe")
	not helpers.is_comment_line(line)
	some re in [
		concat("", [`\bhttp\.ListenAndServe\(\s*`, _wild, `\s*,\s*([\w\.]+)\s*\)`]),
		concat("", [`\bhttp\.ListenAndServeTLS\(\s*`, _wild, `\s*,[^,]+,[^,]+,\s*([\w\.]+)\s*\)`]),
	]
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) > 0
	_debug_handler(m[0][1], muxes)
	finding := _finding(path, i, line)
}

# &http.Server{Addr: ":6060", Handler: h} — no Handler means the default mux.
findings contains finding if {
	some path, content in input.file_contents
	_go_file(path, content)
	contains(content, "http.Server{")
	lines := split(content, "\n")
	muxes := _debug_muxes(lines)
	some i, line in lines
	contains(line, "Addr")
	regex.match(concat("", [`^\s*(?:.*http\.Server\{\s*)?Addr:\s*`, _wild, `\s*,?\s*(?:\}.*)?$`]), line)
	_server_literal_open(lines, i)
	h := _server_handler(lines, i)
	_debug_handler(h, muxes)
	finding := _finding(path, i, line)
}

_server_literal_open(lines, i) if contains(lines[i], "http.Server{")

_server_literal_open(lines, i) if {
	some j in numbers.range(max([0, i - 3]), i - 1)
	contains(lines[j], "http.Server{")
}

# The Handler field of the literal containing line i ("nil" when absent).
_server_handler(lines, i) := h if {
	hs := [r[0][1] |
		some j in numbers.range(max([0, i - 3]), min([count(lines) - 1, i + 12]))
		r := regex.find_all_string_submatch_n(`\bHandler:\s*([\w\.]+)`, lines[j], 1)
		count(r) > 0
		_same_literal(lines, i, j)
	]
	h := _first_or_nil(hs)
}

_first_or_nil(hs) := hs[0] if count(hs) > 0

_first_or_nil(hs) := "nil" if count(hs) == 0

# Lines i and j sit in the same struct literal: no closing brace of the
# literal between them.
_same_literal(_, i, i)

_same_literal(lines, i, j) if {
	j > i
	not _closes(lines, i, j - 1)
}

_same_literal(lines, i, j) if {
	j < i
	not _closes(lines, j, i - 1)
}

_closes(lines, a, b) if {
	some k in numbers.range(a, b)
	regex.match(`^\s*\}`, lines[k])
}

# ln, err := net.Listen("tcp", ":9090") ... http.Serve(ln, handler)
findings contains finding if {
	some path, content in input.file_contents
	_go_file(path, content)
	contains(content, "http.Serve")
	lines := split(content, "\n")
	muxes := _debug_muxes(lines)
	some i, line in lines
	contains(line, "net.Listen")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*(\w+)\s*,\s*\w+\s*:?=\s*net\.Listen\(\s*"tcp[46]?"\s*,\s*`, _wild, `\s*\)`]), line, 1)
	count(m) > 0
	ln := m[0][1]
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 15]))
	s := regex.find_all_string_submatch_n(concat("", [`\bhttp\.Serve(?:TLS)?\(\s*`, ln, `\s*,\s*([\w\.]+)`]), lines[j], 1)
	count(s) > 0
	_debug_handler(s[0][1], muxes)
	finding := _finding(path, i, line)
}

# gin-contrib/pprof: pprof.Register(r) then r.Run() / r.Run(":8080")
findings contains finding if {
	some path, content in input.file_contents
	_go_file(path, content)
	contains(content, "github.com/gin-contrib/pprof")
	lines := split(content, "\n")
	engines := {e |
		some l in lines
		not helpers.is_comment_line(l)
		r := regex.find_all_string_submatch_n(`\bpprof\.Register\(\s*(\w+)`, l, 1)
		count(r) > 0
		e := r[0][1]
	}
	some i, line in lines
	contains(line, ".Run(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`\b(\w+)\.Run\(\s*(?:`, _wild, `)?\s*\)`]), line, 1)
	count(m) > 0
	m[0][1] in engines
	finding := _finding(path, i, line)
}

# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_209

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-209",
	"name": "Generation of Error Message Containing Sensitive Information",
	"description": "A stack trace or a database error message is sent to the client in an HTTP response, telling an attacker the file layout, framework versions, SQL text and schema behind the failure. Reported: Python traceback.format_exc()/format_exception()/format_tb()/format_stack() passed to a response (jsonify, make_response, HttpResponse, JsonResponse, FastAPI JSONResponse, Response, render_template, abort, self.write), directly, through a variable (or a dict) assigned from it on a line above, or returned bare or stored in an error dict that is returned in a module that imports a web framework (outside logging formatter methods), traceback.print_exc(file=self.wfile/response), and str(e) of a caught database exception (sqlite3.Error, psycopg2, DatabaseError, OperationalError, IntegrityError, SQLAlchemyError, pymysql/MySQLdb) in a response; Java e.printStackTrace(response.getWriter()) or into a PrintWriter assigned from the response, e.printStackTrace(new PrintWriter(sw)) followed by sw.toString() in a body or a controller's return, ExceptionUtils.getStackTrace/Throwables.getStackTraceAsString in a return, body or writer, and the getMessage()/toString() of a caught SQLException (or DataAccessException, PSQLException, PersistenceException) written to output, a writer or a return value; JavaScript/TypeScript err.stack/error.stack/e.stack inside res.send/json/end/write/render (also with the res.status(...).json(...) chain broken over lines), ctx.body or reply.send, directly, in a template literal or object, or through a variable assigned from it, unless the stack is selected only outside production (NODE_ENV/isDev/debug ternary or &&, or an if block on NODE_ENV/isDev a few lines above); PHP die/exit/echo/print of mysqli_error(), mysqli_connect_error(), mysql_error(), pg_last_error(), $db->error, $db->connect_error, getTraceAsString() or a caught PDOException's getMessage(), ini_set('display_errors', 1|'On'), and display_errors = On in php.ini or .htaccess; Go runtime/debug.Stack(), or the buffer filled by runtime.Stack(buf, ...), written to the http.ResponseWriter (w.Write, fmt.Fprint*(w, ...), http.Error, gin c.String/JSON); C# ex.StackTrace or ex.ToString() returned by Content/Ok/BadRequest/StatusCode/Problem/Json or Response.Write, and the Message of a caught SqlException/SQLiteException/DbException/MySqlException/NpgsqlException returned the same way or assigned to a WebForms control's Text; Spring Boot server.error.include-stacktrace=always and include-exception=true; ASP.NET customErrors mode=\"Off\" and httpErrors errorMode=\"Detailed\". Not reported: traces and messages written to a log, stderr or error_log, a generic message returned to the client, traceback.print_exc() to stderr, a trace returned from a helper in a module with no web framework (crash files, logging formatters), exception messages other than database ones (so WebForms lblError.Text = ex.Message on a generic Exception is not reported), a trace or message carried to the response through a helper function or another file, the patterns in comments or string literals, and test code.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-209/",
	"languages": ["java", "node", "python", "php", "go", "csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [209],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["error-handling", "stack-trace", "information-exposure", "cwe-209"],
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_msg_trace := "Stack trace sent to the client: it discloses file paths, library versions and code structure. Log the trace server-side and return a generic error with a correlation id"

_msg_db := "Database error message sent to the client: it discloses SQL text, schema and driver details that help an attacker shape an injection. Log it server-side and return a generic error"

_msg_cfg := "Detailed error output is enabled: every unhandled exception shows its stack trace or message to the client. Disable it for production and log errors server-side"

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_ext(path, exts) if {
	some e in exts
	endswith(path, e)
}

_base(path) := regex.replace(path, `^.*/`, "")

# Remove quoted string literals (not template literals) so a pattern quoted in
# a help text or message is not mistaken for code.
_strip_q(s) := regex.replace(s, `"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'`, `""`)

_pd(l) := count(split(l, "(")) - count(split(l, ")"))

# The call opened on line i, up to its closing parenthesis (at most 8 lines).
_call_text(lines, i) := txt if {
	last := min([count(lines) - 1, i + 8])
	ends := [j |
		some j in numbers.range(i, last)
		sum([_pd(lines[k]) | some k in numbers.range(i, j)]) <= 0
	]
	e := min(array.concat([last], ends))
	txt := concat("\n", array.slice(lines, i, e + 1))
}

_ident_in(v, s) if regex.match(concat("", [`(^|[^\w.])`, v, `\b`]), s)

# ── Python ───────────────────────────────────────────────────────────────

_py_trace := `\btraceback\.format_(exc|exception|tb|stack)\s*\(|(^|[^\w.])format_exc\s*\(`

_py_resp_sink := `\b(jsonify|make_response|HttpResponse|HttpResponseServerError|JsonResponse|JSONResponse|ORJSONResponse|UJSONResponse|Response|PlainTextResponse|HTMLResponse|render_template|render|abort|HTTPException|json_response)\s*\(|\b(self\.wfile|wfile|self|response|resp)\.write\s*\(`

_py_logging := `\b(log|logger|logging|LOG|LOGGER|_log|_logger|app\.logger|current_app\.logger)\.\w+\s*\(|\bprint\s*\(|stderr`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "traceback")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "format_")
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(_py_trace, code)
	_py_reported(lines, i, code, content)
	f := _finding(path, i, line, _msg_trace)
}

# A module that serves HTTP: only there is a bare `return` a response.
_py_web(content) if regex.match(`(?m)^\s*(from|import)\s+(flask|django|fastapi|starlette|aiohttp|tornado|bottle|pyramid|sanic|falcon|quart|werkzeug|rest_framework|graphene|flask_graphql|graphql_server|http\.server)\b`, content)

# The trace is an argument of a response call on the same line.
_py_reported(_, _, code, _) if {
	regex.match(_py_resp_sink, code)
	not regex.match(_py_logging, code)
}

# A bare return of the trace, in a module that serves HTTP and not inside a
# logging formatter method.
_py_reported(lines, i, code, content) if {
	regex.match(`\breturn\b`, code)
	not regex.match(_py_resp_sink, code)
	not regex.match(_py_logging, code)
	_py_web(content)
	not _py_in_formatter(lines, i)
}

_py_in_formatter(lines, i) if {
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`^\s*def\s+(formatException|formatStack|format|format_exception|emit)\s*\(`, lines[j])
}

# err["debug"] = traceback.format_exc() ... return err
_py_reported(lines, i, code, content) if {
	_py_web(content)
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*\[[^=]*\]\s*=\s*[^=]`, code, 1)
	count(m) > 0
	v := m[0][1]
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 12]))
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`^\s*return\b.*\b`, v, `\b`]), l)
}

# tb = traceback.format_exc() ... return make_response(tb, 500)
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "traceback")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "format_")
	not helpers.is_comment_line(line)
	regex.match(`^\s*[A-Za-z_]\w*\s*=\s*[^=].*?\b(traceback\.)?format_(exc|exception|tb|stack)\s*\(`, line)
	not regex.match(_py_logging, line)
	v := helpers.assigned_first(line)
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_py_resp_sink, l)
	not regex.match(_py_logging, l)
	_ident_in(v, _strip_q(_call_text(lines, j)))
	f := _finding(path, j, l, _msg_trace)
}

# return HttpResponse(\n "".join(traceback.format_exception(...)))
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "traceback")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_py_resp_sink, line)
	not regex.match(_py_trace, line)
	not regex.match(_py_logging, line)
	_pd(line) > 0
	txt := _strip_q(_call_text(lines, i))
	regex.match(`\btraceback\.format_(exc|exception|tb|stack)\s*\(`, txt)
	f := _finding(path, i, line, _msg_trace)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "print_exc")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "print_exc")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`print_exc\s*\([^)]*\bfile\s*=\s*([\w.]+)`, line, 1)
	count(m) > 0
	regex.match(`(?i)wfile|response|\bresp\b|\bres\b|request|writer|socket|conn`, m[0][1])
	f := _finding(path, i, line, _msg_trace)
}

# except sqlite3.Error as exc: return jsonify({"error": str(exc)}), 500
_py_db_exc := `^\s*except\b[^:]*\b(sqlite3\.\w*Error|psycopg2?\.\w+|DatabaseError|OperationalError|ProgrammingError|IntegrityError|DataError|SQLAlchemyError|DBAPIError|MySQLdb\.\w+|pymysql\.\w+|mysql\.connector\.\w+)\b[^:]*\bas\s+(\w+)\s*:`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)^\s*except\b[^:\n]*\b(sqlite3|psycopg|Database|Operational|Programming|Integrity|DataError|SQLAlchemy|DBAPI|MySQLdb|pymysql|mysql\.connector)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some c, cl in lines
	contains(cl, "except")
	m := regex.find_all_string_submatch_n(_py_db_exc, cl, 1)
	count(m) > 0
	v := m[0][2]
	some i in numbers.range(c + 1, min([count(lines) - 1, c + 6]))
	line := lines[i]
	not helpers.is_comment_line(line)
	not regex.match(_py_logging, line)
	_py_out_line(line, content)
	regex.match(concat("", [`\b(str|repr)\(\s*`, v, `\s*\)|\{`, v, `[!:}.]|\b`, v, `\.(args|orig|pgerror|msg)\b|%\s*\(?\s*`, v, `\b|[(,]\s*`, v, `\s*[,)]`]), line)
	f := _finding(path, i, line, _msg_db)
}

_py_out_line(line, _) if regex.match(_py_resp_sink, line)

_py_out_line(line, content) if {
	regex.match(`^\s*return\b`, line)
	_py_web(content)
}

# ── Java ─────────────────────────────────────────────────────────────────

_java_file(path) if _ext(path, {".java", ".jsp"})

_java_logging := `\b(log|logger|LOG|LOGGER|LOGGER_\w+|\w*[lL]ogger|\w*Log)\.\w+\s*\(|System\.(out|err)\.`

# printStackTrace(response.getWriter()), or into a writer taken from the response.
findings contains f if {
	some path, content in input.file_contents
	_java_file(path)
	contains(content, "printStackTrace(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "printStackTrace(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\.printStackTrace\s*\(\s*([^;]+?)\s*\)\s*;`, line, 1)
	count(m) > 0
	_java_resp_writer(lines, i, m[0][1], path)
	f := _finding(path, i, line, _msg_trace)
}

_java_resp_writer(_, _, arg, _) if regex.match(`(?i)(response|resp)\w*\.get(Writer|OutputStream)\s*\(`, arg)

_java_resp_writer(_, _, arg, path) if {
	endswith(path, ".jsp")
	regex.match(`\bout\b`, arg)
}

_java_resp_writer(lines, i, arg, _) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	some j in numbers.range(max([0, i - 40]), i - 1)
	l := lines[j]
	contains(l, arg)
	regex.match(concat("", [`\b`, arg, `\s*=\s*(new\s+PrintWriter\s*\(\s*)?\w*(response|resp)\w*\.get(Writer|OutputStream)\s*\(`]), l)
}

# e.printStackTrace(new PrintWriter(sw)); ... .body(sw.toString())
findings contains f if {
	some path, content in input.file_contents
	_java_file(path)
	contains(content, "printStackTrace(new PrintWriter(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "printStackTrace(new PrintWriter(")
	not helpers.is_comment_line(al)
	m := regex.find_all_string_submatch_n(`\.printStackTrace\(new PrintWriter\(\s*(\w+)\s*[,)]`, al, 1)
	count(m) > 0
	sw := m[0][1]
	some i in numbers.range(a + 1, min([count(lines) - 1, a + 6]))
	line := lines[i]
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(concat("", [`\b`, sw, `\b(\s*\.\s*(toString|getBuffer)\s*\(\s*\))?`]), code)
	not regex.match(_java_logging, code)
	_java_trace_out(code, content)
	f := _finding(path, i, line, _msg_trace)
}

_java_web(content) if regex.match(`@(Rest)?Controller\b|@(Get|Post|Put|Delete|Patch|Request|Exception)(Mapping|Handler)\b|\bHttpServlet\b|@Path\(|@GET\b`, content)

# A response sink, or a bare return from a controller or servlet.
_java_trace_out(code, _) if {
	regex.match(_java_sink, code)
	not regex.match(`^\s*return\b`, code)
}

_java_trace_out(code, _) if regex.match(`^\s*return\b.*(\.body\s*\(|\.entity\s*\(|\bok\s*\()`, code)

_java_trace_out(code, content) if {
	regex.match(`^\s*return\b`, code)
	_java_web(content)
}

_java_trace := `\b(ExceptionUtils\.(getStackTrace|getFullStackTrace)|Throwables\.getStackTraceAsString)\s*\(|Arrays\.toString\s*\(\s*\w+\.getStackTrace\s*\(\s*\)`

_java_sink := `\breturn\b|\.body\s*\(|\.get(Writer|OutputStream)\s*\(\s*\)|\bout\.print|\.write\s*\(|\.output\s*\(|\.addAttribute\s*\(|\.sendError\s*\(|\bok\s*\(|\.entity\s*\(`

findings contains f if {
	some path, content in input.file_contents
	_java_file(path)
	_has_any(content, {"ExceptionUtils", "Throwables", "getStackTrace"})
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "StackTrace")
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(_java_trace, code)
	regex.match(_java_sink, code)
	not regex.match(_java_logging, code)
	f := _finding(path, i, line, _msg_trace)
}

_java_sql_catch := `catch\s*\(\s*(final\s+)?([\w.]+\.)?(SQLException|SQL\w*Exception|DataAccessException|BadSqlGrammarException|JDBCException|PSQLException|PersistenceException|HibernateException)(\s*\|\s*[\w.]+)*\s+(\w+)\s*\)`

findings contains f if {
	some path, content in input.file_contents
	_java_file(path)
	contains(content, "catch")
	_has_any(content, {"SQLException", "DataAccessException", "SqlGrammar", "JDBCException", "PersistenceException", "HibernateException"})
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some c, cl in lines
	contains(cl, "catch")
	m := regex.find_all_string_submatch_n(_java_sql_catch, cl, 1)
	count(m) > 0
	v := m[0][5]
	some i in numbers.range(c, min([count(lines) - 1, c + 8]))
	line := lines[i]
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(concat("", [`\b`, v, `\.(getMessage|getLocalizedMessage|toString)\s*\(\s*\)|\+\s*`, v, `\s*[+;)]`]), code)
	regex.match(_java_sink, code)
	not regex.match(_java_logging, code)
	f := _finding(path, i, line, _msg_db)
}

# Spring Boot error attributes that put the trace or exception in the body.
_spring_cfg(path) if regex.match(`^(application|bootstrap)[\w.-]*\.(properties|ya?ml)$`, _base(path))

findings contains f if {
	some path, content in input.file_contents
	_spring_cfg(path)
	_has_any(content, {"include-stacktrace", "include-exception", "includeStacktrace", "includeException"})
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	not startswith(trim_space(line), "!")
	regex.match(`(?i)include-?stacktrace\s*[=:]\s*["']?always\b|include-?exception\s*[=:]\s*["']?true\b`, line)
	f := _finding(path, i, line, _msg_cfg)
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_file(path) if {
	_ext(path, {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
	not endswith(path, ".min.js")
}

_js_sink := `\b(res|resp|response|reply)\s*(\.\s*(status|code)\s*\([^)]*\)\s*)?\.\s*(send|json|jsonp|end|write|render)\s*\(|\bctx\.body\s*=`

_js_stack := `(?i)\b(e|ex|err|error|exception|\w+err|\w+error)\s*\??\.\s*stack\b`

findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, ".stack")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	_js_sink_at(lines, i, line)
	regex.match(_js_stack, _strip_q(_js_unguard(_call_text(lines, i))))
	not _js_dev_block(lines, i)
	f := _finding(path, i, line, _msg_trace)
}

_js_sink_at(_, _, line) if regex.match(_js_sink, line)

# res\n  .status(500)\n  .json({...}): the chain broken over lines.
_js_sink_at(lines, i, line) if {
	regex.match(`^\s*\.\s*(send|json|jsonp|end|write|render)\s*\(`, line)
	prefix := concat("", [trim_space(lines[k]) | some k in numbers.range(max([0, i - 3]), i - 1)])
	regex.match(`(^|[^\w.$])(res|resp|response|reply)(\.(status|code)\([^)]*\))?$`, prefix)
}

# A stack shown only outside production (NODE_ENV/isDev/debug ternary or &&, or an if block on NODE_ENV/isDev a few lines above)
# is removed before the test.
_js_unguard(s) := regex.replace(s, `(?i)(NODE_ENV|\bisDev\w*|\bisProd\w*|\bdebug\w*|\.get\(\s*['"]env['"]\s*\))[^,;\n]*\.stack\b`, "")

# const details = err.stack; ... res.end(details)
findings contains f if {
	some path, content in input.file_contents
	_js_file(path)
	contains(content, ".stack")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, ".stack")
	not helpers.is_comment_line(al)
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*\w+\s*)?=\s*(.*)$`, al, 1)
	count(m) > 0
	regex.match(_js_stack, _strip_q(m[0][2]))
	v := m[0][1]
	some i in numbers.range(a + 1, min([count(lines) - 1, a + 8]))
	line := lines[i]
	not helpers.is_comment_line(line)
	regex.match(_js_sink, line)
	not regex.match(_js_stack, _strip_q(_call_text(lines, i)))
	_ident_in(v, _strip_q(_call_text(lines, i)))
	not _js_dev_block(lines, i)
	f := _finding(path, i, line, _msg_trace)
}

# The sink sits inside an `if` block that runs only outside production.
_js_dev_guard := `(?i)\bif\s*\(.*(NODE_ENV\s*===?\s*['"]dev|NODE_ENV\s*!==?\s*['"]prod|['"]dev\w*['"]\s*===?\s*\S*NODE_ENV|\bisDev\w*|\bisDebug\w*|\.get\(\s*['"]env['"]\s*\)\s*===?\s*['"]dev)`

_js_dev_block(lines, i) if {
	some j in numbers.range(max([0, i - 4]), i - 1)
	regex.match(_js_dev_guard, lines[j])
	not _js_block_closed(lines, j, i)
}

_js_block_closed(lines, j, i) if {
	some k in numbers.range(j + 1, i - 1)
	regex.match(`^\s*\}`, lines[k])
}

# ── PHP ──────────────────────────────────────────────────────────────────

_php_out := `(?i)(^|[^\w$>:])(die|exit|echo|print|print_r|var_dump|var_export|printf)\b`

_php_db_err := `\b(mysqli_error|mysqli_connect_error|mysqli_stmt_error|mysql_error|pg_last_error|pg_result_error|sqlsrv_errors|oci_error)\s*\(|->(connect_)?error\s*($|[;.,)\]}]|\s+[^(\s])|->errorInfo\s*\(|->getTraceAsString\s*\(|->getTrace\s*\(`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_has_any(content, {"_error", "->error", "getTrace", "errorInfo"})
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"_error", "->error", "getTrace", "errorInfo"})
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(_php_db_err, code)
	regex.match(_php_out, code)
	not regex.match(`\berror_log\s*\(`, code)
	f := _finding(path, i, line, _php_msg(code))
}

_php_msg(code) := _msg_trace if regex.match(`->getTrace`, code)

_php_msg(code) := _msg_db if not regex.match(`->getTrace`, code)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "PDOException")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some c, cl in lines
	contains(cl, "catch")
	m := regex.find_all_string_submatch_n(`catch\s*\(\s*\\?(PDOException|mysqli_sql_exception)\s+\$(\w+)\s*\)`, cl, 1)
	count(m) > 0
	v := m[0][2]
	some i in numbers.range(c, min([count(lines) - 1, c + 6]))
	line := lines[i]
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(concat("", [`\$`, v, `->getMessage\s*\(`]), code)
	regex.match(_php_out, code)
	f := _finding(path, i, line, _msg_db)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "display_errors")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "display_errors")
	not helpers.is_comment_line(line)
	regex.match(`(?i)\bini_set\s*\(\s*["']display_errors["']\s*,\s*(1|true|on|["'](1|on|true|yes)["'])\s*\)`, line)
	f := _finding(path, i, line, _msg_cfg)
}

findings contains f if {
	some path, content in input.file_contents
	_php_ini(path)
	contains(content, "display_errors")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "display_errors")
	regex.match(`(?i)^\s*(display_errors\s*=\s*["']?(on|1|true|yes)["']?\s*$|php_(flag|value)\s+display_errors\s+["']?(on|1)\b)`, line)
	f := _finding(path, i, line, _msg_cfg)
}

_php_ini(path) if endswith(path, ".ini")

_php_ini(path) if _base(path) == ".htaccess"

_php_ini(path) if regex.match(`^php\.ini`, _base(path))

# ── Go ───────────────────────────────────────────────────────────────────

_go_sink := `\b(w|rw|resp|res|writer|wr)\.Write\s*\(|\bfmt\.Fprint\w*\s*\(\s*(w|rw|resp|res|writer|wr|c\.Writer|ctx\.Writer)\s*,|\bhttp\.Error\s*\(|\b(c|ctx)\.(String|JSON|Data|AbortWithStatusJSON|IndentedJSON|HTML|Send|SendString)\s*\(|\bio\.WriteString\s*\(\s*(w|rw|resp|res|writer)\s*,`

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "debug.Stack()")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "debug.Stack()")
	not helpers.is_comment_line(line)
	regex.match(_go_sink, line)
	f := _finding(path, i, line, _msg_trace)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "debug.Stack()")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "debug.Stack()")
	regex.match(`^\s*[A-Za-z_]\w*\s*:?=\s*(string\()?debug\.Stack\(\)`, al)
	v := helpers.assigned_first(al)
	some i in numbers.range(a + 1, min([count(lines) - 1, a + 8]))
	line := lines[i]
	not helpers.is_comment_line(line)
	regex.match(_go_sink, line)
	_ident_in(v, _strip_q(line))
	f := _finding(path, i, line, _msg_trace)
}

# n := runtime.Stack(buf, false) ... w.Write(buf[:n])
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "runtime.Stack(")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some a, al in lines
	contains(al, "runtime.Stack(")
	not helpers.is_comment_line(al)
	m := regex.find_all_string_submatch_n(`\bruntime\.Stack\(\s*(\w+)\s*,`, al, 1)
	count(m) > 0
	buf := m[0][1]
	some i in numbers.range(a, min([count(lines) - 1, a + 8]))
	line := lines[i]
	not helpers.is_comment_line(line)
	regex.match(_go_sink, line)
	_ident_in(buf, _strip_q(line))
	f := _finding(path, i, line, _msg_trace)
}

# ── C# / ASP.NET ─────────────────────────────────────────────────────────

# catch (SqlException ex) { return StatusCode(500, ex.Message); }
findings contains f if {
	some path, content in input.file_contents
	_ext(path, {".cs", ".cshtml", ".aspx"})
	regex.match(`catch\s*\(\s*[\w.]*(SqlException|SQLiteException|SqliteException|DbException|MySqlException|NpgsqlException|OracleException|DbUpdateException)\b`, content)
	not helpers.is_test_path(path)
	not regex.match(`(^|/)[^/]*Tests?[^/]*/`, path)
	lines := split(content, "\n")
	some c, cl in lines
	contains(cl, "catch")
	m := regex.find_all_string_submatch_n(`catch\s*\(\s*[\w.]*(SqlException|SQLiteException|SqliteException|DbException|MySqlException|NpgsqlException|OracleException|DbUpdateException)\s+(\w+)\s*\)`, cl, 1)
	count(m) > 0
	v := m[0][2]
	some i in numbers.range(c, min([count(lines) - 1, c + 8]))
	line := lines[i]
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(concat("", [`\b`, v, `\.(Message|ToString\s*\(\s*\)|InnerException)`]), code)
	regex.match(concat("|", [_cs_sink, `^\s*\w+\.(Text|InnerHtml|InnerText)\s*=`]), code)
	not regex.match(`\b_?[lL]og(ger)?\.\w+\s*\(`, code)
	f := _finding(path, i, line, _msg_db)
}

_cs_sink := `\b(Content|Ok|BadRequest|StatusCode|Problem|Json|ObjectResult|NotFound|UnprocessableEntity)\s*\(|\bResponse\.Write(Async)?\s*\(|\.WriteAsync\s*\(`

findings contains f if {
	some path, content in input.file_contents
	_ext(path, {".cs", ".cshtml", ".aspx"})
	_has_any(content, {"StackTrace", "ToString()"})
	not helpers.is_test_path(path)
	not regex.match(`(^|/)[^/]*Tests?[^/]*/`, path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"StackTrace", "ToString()"})
	not helpers.is_comment_line(line)
	code := _strip_q(line)
	regex.match(`\b(ex|e|exc|exception|err|error)\.(StackTrace|ToString\s*\(\s*\))`, code)
	regex.match(_cs_sink, code)
	not regex.match(`\b_?[lL]ogger\.\w+\s*\(`, code)
	f := _finding(path, i, line, _msg_trace)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(lower(path), ".config")
	_has_any(content, {"customErrors", "httpErrors"})
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)<customErrors\b[^>]*\bmode\s*=\s*["']off["']|<httpErrors\b[^>]*\berrorMode\s*=\s*["']detailed["']`, line)
	not regex.match(`^\s*<!--`, line)
	f := _finding(path, i, line, _msg_cfg)
}

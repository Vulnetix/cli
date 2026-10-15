# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_430

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-430",
	"name": "Deployment of Wrong Handler",
	"description": "The static-file handler is deployed on the application's own directory, so requests for server source, configuration and secrets (server.js, app.py, settings.py, .env, package.json) are answered by the handler meant for public assets instead of being refused. Reported in JavaScript/TypeScript: express.static, serve-static, serve-index, koa-static and @fastify/static (root:) given the project or source directory: __dirname, process.cwd(), '.', './', '..', '', path.join/path.resolve of __dirname or '.' with nothing below it ('', '/', '.', '..'), path.dirname(fileURLToPath(import.meta.url)), `${__dirname}`, __dirname + '/', or a variable assigned one of those up to fifty lines above; a call broken after its opening parenthesis or a comma is read with its next line. In Python: Flask static_folder, Starlette/FastAPI StaticFiles(directory=...), send_from_directory with a variable file name, aiohttp add_static, Tornado StaticFileHandler {\"path\": ...} and static_path, Bottle static_file(..., root=...) and Django STATICFILES_DIRS given '.', '', os.getcwd(), os.path.dirname(__file__), os.path.abspath(os.path.dirname(__file__)), Path(__file__).parent, Path.cwd(), app.root_path or BASE_DIR, directly or through such a variable. Not reported: send_from_directory of a literal file name (favicon.ico, robots.txt), bundler and dev-server settings (webpack devServer, vite root), a dedicated subdirectory (path.join(__dirname, 'public'), static_folder='static/', BASE_DIR / 'static'), directories chosen at run time, test files, comments and string literals. A broad exception handler is not a wrong handler and is not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-430/",
	"languages": ["node", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [430],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["deployment-of-wrong-handler", "static-files", "source-disclosure", "cwe-430"],
}

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

_needles := {
	"js": {"static", "Static", "serveIndex", "serve(", "root"},
	"py": {"static_folder", "StaticFiles", "send_from_directory", "add_static", "STATICFILES_DIRS", "StaticFileHandler", "static_file", "static_path"},
}

_has_needle(lang, s) if {
	some n in _needles[lang]
	contains(s, n)
}

# The project or source directory, written as a whole argument.
_root := {
	"js": concat("", [
		`(?:__dirname|process\.cwd\(\)|['"]\.{0,2}/?['"]`,
		`|path\.(?:join|resolve)\(\s*(?:__dirname|process\.cwd\(\)|['"]\.{1,2}/?['"])\s*(?:,\s*['"]\.{0,2}/?['"]\s*)?\)`,
		`|path\.dirname\(\s*(?:url\.)?fileURLToPath\(\s*import\.meta\.url\s*\)\s*\)`,
		`|path\.resolve\(\s*\)|`,
		"`\\$\\{__dirname\\}/?`",
		`|__dirname\s*\+\s*['"]/?['"])`,
	]),
	"py": concat("", [
		`(?:['"]\.?/?['"]|os\.getcwd\(\)|os\.curdir`,
		`|os\.path\.dirname\(\s*(?:os\.path\.(?:abspath|realpath)\(\s*)?__file__\s*\)?\s*\)`,
		`|os\.path\.(?:abspath|realpath)\(\s*(?:['"]\.['"]|os\.path\.dirname\(\s*__file__\s*\))\s*\)`,
		`|Path\(\s*__file__\s*\)(?:\.(?:resolve|absolute)\(\))?\.parent(?:\.parent)*`,
		`|Path\(\s*(?:['"]\.['"])?\s*\)|Path\.cwd\(\)`,
		`|(?:current_)?app\.root_path|BASE_DIR|PROJECT_ROOT|ROOT_DIR)`,
	]),
}

_ident := {"js": `[A-Za-z_$][\w$]*`, "py": `[A-Za-z_]\w*`}

_arg(lang) := concat("", [`(`, _root[lang], `|`, _ident[lang], `)`])

_sinks(lang, _) := {
	concat("", [`\b(?:express\.static|serveStatic|serveIndex|koaStatic|staticCache)\s*\(\s*`, _arg(lang), `\s*[,)]`]),
	concat("", [`\brequire\(\s*['"](?:serve-static|serve-index|koa-static)['"]\s*\)\s*\(\s*`, _arg(lang), `\s*[,)]`]),
} if lang == "js"

_koa_sinks(content) := {concat("", [`(?:^|[^\w.])serve\s*\(\s*`, _arg("js"), `\s*[,)]`])} if contains(content, "koa-static")

_koa_sinks(content) := set() if not contains(content, "koa-static")

_fastify_sinks(content) := {concat("", [`\broot\s*:\s*`, _arg("js"), `\s*(?:[,}]|$)`])} if regex.match(`@fastify/static|fastify-static`, content)

_fastify_sinks(content) := set() if not regex.match(`@fastify/static|fastify-static`, content)

_extra_sinks("js", content) := _koa_sinks(content) | _fastify_sinks(content)

_extra_sinks("py", _) := set()

_sinks(lang, _) := {
	concat("", [`\bstatic_folder\s*=\s*`, _arg(lang), `\s*[,)]`]),
	concat("", [`\bStaticFiles\(\s*directory\s*=\s*`, _arg(lang), `\s*[,)]`]),
	# A literal file name (favicon.ico, robots.txt) serves one fixed file.
	concat("", [`\bsend_from_directory\(\s*`, _arg(lang), `\s*,\s*[A-Za-z_]`]),
	concat("", [`\bStaticFileHandler\s*,\s*\{\s*['"]path['"]\s*:\s*`, _arg(lang), `\s*[,}]`]),
	concat("", [`(?:\bstatic_path\s*=|['"]static_path['"]\s*:)\s*`, _arg(lang), `\s*[,)}]`]),
	concat("", [`\bstatic_file\(\s*[^,()'"]+,\s*root\s*=\s*`, _arg(lang), `\s*[,)]`]),
	concat("", [`\badd_static\(\s*['"][^'"]*['"]\s*,\s*(?:path\s*=\s*)?`, _arg(lang), `\s*[,)]`]),
	concat("", [`\bSTATICFILES_DIRS\s*=\s*[\[(]\s*`, _arg(lang), `\s*,?\s*[\])]`]),
} if lang == "py"

_decl := {"js": `^\s*(?:export\s+)?(?:const|let|var)\s+`, "py": `^\s*`}

_root_assigned(lang, lines, i, arg) if regex.match(concat("", [`^`, _root[lang], `$`]), arg)

_root_assigned(lang, lines, i, arg) if {
	not regex.match(concat("", [`^`, _root[lang], `$`]), arg)
	i > 0
	re := concat("", [_decl[lang], arg, `\s*(?::\s*\w+\s*)?=\s*`, _root[lang], `\s*;?\s*$`])
	some j in numbers.range(max([0, i - 50]), i - 1)
	regex.match(re, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_needle(lang, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	sinks := _sinks(lang, content) | _extra_sinks(lang, content)
	some i, line in lines
	_has_needle(lang, line)
	not helpers.is_comment_line(line)
	text := _text(lines, i)
	some re in sinks
	some m in regex.find_all_string_submatch_n(re, text, -1)
	indexof(text, m[0]) < count(line)
	not _in_string(text, m[0])
	_root_assigned(lang, lines, i, m[1])
	finding := {
		"rule_id": metadata.id,
		"message": "The static-file handler serves the application's own directory: server source, configuration and secrets become downloadable. Serve a dedicated public/static subdirectory instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A call broken after "(" or "," continues on the next line.
_text(lines, i) := concat(" ", [lines[i], trim_space(lines[i + 1])]) if {
	i + 1 < count(lines)
	regex.match(`[(,]\s*$`, lines[i])
}

_text(lines, i) := lines[i] if {
	not regex.match(`[(,]\s*$`, lines[i])
}

_text(lines, i) := lines[i] if i + 1 == count(lines)

# The match sits inside a string literal: a quote opens before it on the line
# and is still open when the match starts.
_in_string(line, match) if {
	idx := indexof(line, match)
	idx > 0
	before := substring(line, 0, idx)
	_odd_quotes(before)
}

_odd_quotes(s) if count(regex.find_all_string_submatch_n(`"`, regex.replace(s, `\\.`, ""), -1)) % 2 == 1

_odd_quotes(s) if count(regex.find_all_string_submatch_n(`'`, regex.replace(s, `\\.`, ""), -1)) % 2 == 1

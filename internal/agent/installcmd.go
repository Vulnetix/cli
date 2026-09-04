// Package agent implements the coding-agent surface: the hook engine that
// answers a tool call, and the installer that wires a host up to it.
//
// The design constraint the whole package serves: a coding agent only learns
// what its hooks tell it. Silence is the correct output whenever the repository
// policy is satisfied, and everything else has to be worth an interruption.
package agent

import (
	"strings"
)

// Candidate is one package an agent is about to add, recovered from the command
// it was about to run.
type Candidate struct {
	// Name is the registry name, scope included for npm.
	Name string
	// Version is the requested version when the command pinned one, empty when
	// the command left resolution to the package manager. Empty is the common
	// case and is not an error: the guard resolves what would be installed.
	Version string
	// Ecosystem is the purl-style ecosystem, matching what VDB expects.
	Ecosystem string
	// Manager is the tool that would perform the install, for the message.
	Manager string
}

// installVerb describes one package manager's add-a-dependency command.
type installVerb struct {
	// argv is the leading token sequence that identifies the command.
	argv []string
	// ecosystem is the purl ecosystem the named packages belong to.
	ecosystem string
	// manager names the tool for reporting.
	manager string
	// valueFlags are flags that consume the following argument, so it is not
	// mistaken for a package name. `npm i -w web axios` must yield axios, not
	// web.
	valueFlags []string
	// separator splits a name from a version, when the ecosystem uses one.
	// Several use "@", but Python pins with operators instead, and Go embeds
	// "@" in a module path that also contains slashes.
	separator string
}

// installVerbs is the full set of commands that can introduce a dependency.
//
// Ordered longest-argv-first at match time, so `uv pip install` is recognised
// before `uv add` cannot match it and `pip install` never claims it.
var installVerbs = []installVerb{
	// ── npm ecosystem ───────────────────────────────────────────────────────
	{argv: []string{"npm", "install"}, ecosystem: "npm", manager: "npm", separator: "@",
		valueFlags: []string{"-w", "--workspace", "--prefix", "--registry", "--tag", "--omit", "--include"}},
	{argv: []string{"npm", "i"}, ecosystem: "npm", manager: "npm", separator: "@",
		valueFlags: []string{"-w", "--workspace", "--prefix", "--registry", "--tag", "--omit", "--include"}},
	{argv: []string{"npm", "add"}, ecosystem: "npm", manager: "npm", separator: "@",
		valueFlags: []string{"-w", "--workspace", "--prefix", "--registry"}},
	{argv: []string{"yarn", "add"}, ecosystem: "npm", manager: "yarn", separator: "@",
		valueFlags: []string{"--cwd", "--registry"}},
	{argv: []string{"pnpm", "add"}, ecosystem: "npm", manager: "pnpm", separator: "@",
		valueFlags: []string{"-w", "--filter", "-F", "--dir", "-C", "--registry"}},
	{argv: []string{"pnpm", "install"}, ecosystem: "npm", manager: "pnpm", separator: "@",
		valueFlags: []string{"-w", "--filter", "-F", "--dir", "-C", "--registry"}},
	{argv: []string{"pnpm", "i"}, ecosystem: "npm", manager: "pnpm", separator: "@",
		valueFlags: []string{"-w", "--filter", "-F", "--dir", "-C", "--registry"}},
	{argv: []string{"bun", "add"}, ecosystem: "npm", manager: "bun", separator: "@",
		valueFlags: []string{"--cwd", "--registry"}},
	{argv: []string{"bun", "install"}, ecosystem: "npm", manager: "bun", separator: "@",
		valueFlags: []string{"--cwd", "--registry"}},
	{argv: []string{"bun", "i"}, ecosystem: "npm", manager: "bun", separator: "@",
		valueFlags: []string{"--cwd", "--registry"}},
	{argv: []string{"yarn", "install"}, ecosystem: "npm", manager: "yarn", separator: "@",
		valueFlags: []string{"--cwd", "--registry"}},
	{argv: []string{"deno", "add"}, ecosystem: "npm", manager: "deno", separator: "@",
		valueFlags: []string{"--config"}},

	// ── Python ──────────────────────────────────────────────────────────────
	// uv pip install must precede uv add's entry so the longer match wins.
	{argv: []string{"uv", "pip", "install"}, ecosystem: "pypi", manager: "uv",
		valueFlags: []string{"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-p", "--python", "--find-links", "-f"}},
	{argv: []string{"uv", "add"}, ecosystem: "pypi", manager: "uv",
		valueFlags: []string{"--optional", "--group", "-p", "--python", "--index", "--package"}},
	{argv: []string{"pip", "install"}, ecosystem: "pypi", manager: "pip",
		valueFlags: []string{"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--find-links", "-f", "--prefix"}},
	{argv: []string{"pip3", "install"}, ecosystem: "pypi", manager: "pip",
		valueFlags: []string{"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--find-links", "-f", "--prefix"}},
	{argv: []string{"poetry", "add"}, ecosystem: "pypi", manager: "poetry",
		valueFlags: []string{"--group", "-G", "--source", "--python", "-E", "--extras"}},
	{argv: []string{"pdm", "add"}, ecosystem: "pypi", manager: "pdm",
		valueFlags: []string{"-G", "--group", "-p", "--project"}},
	{argv: []string{"pipenv", "install"}, ecosystem: "pypi", manager: "pipenv",
		valueFlags: []string{"--python", "--index"}},
	{argv: []string{"conda", "install"}, ecosystem: "pypi", manager: "conda",
		valueFlags: []string{"-n", "--name", "-p", "--prefix", "-c", "--channel"}},

	// ── Go ──────────────────────────────────────────────────────────────────
	// Go separates with "@" but the name is a slash-bearing module path, so
	// splitting takes the last "@" rather than the first.
	{argv: []string{"go", "get"}, ecosystem: "golang", manager: "go", separator: "@last"},
	{argv: []string{"go", "install"}, ecosystem: "golang", manager: "go", separator: "@last"},

	// ── Rust ────────────────────────────────────────────────────────────────
	{argv: []string{"cargo", "add"}, ecosystem: "cargo", manager: "cargo", separator: "@",
		valueFlags: []string{"--features", "-F", "--rename", "--manifest-path", "-p", "--package", "--registry", "--git", "--path", "--branch", "--tag", "--rev"}},

	// ── Ruby ────────────────────────────────────────────────────────────────
	{argv: []string{"gem", "install"}, ecosystem: "rubygems", manager: "gem",
		valueFlags: []string{"-v", "--version", "-i", "--install-dir", "-s", "--source"}},
	{argv: []string{"bundle", "add"}, ecosystem: "rubygems", manager: "bundler",
		valueFlags: []string{"-v", "--version", "--group", "-g", "--source", "--git", "--path"}},

	// ── PHP ─────────────────────────────────────────────────────────────────
	{argv: []string{"composer", "require"}, ecosystem: "packagist", manager: "composer", separator: ":",
		valueFlags: []string{"--working-dir", "-d", "--prefer-install"}},

	// ── .NET ────────────────────────────────────────────────────────────────
	// `dotnet add [PROJECT] package NAME` — the optional project argument sits
	// between the verb and the keyword, so the keyword anchors the scan.
	{argv: []string{"dotnet", "add"}, ecosystem: "nuget", manager: "dotnet",
		valueFlags: []string{"-v", "--version", "-f", "--framework", "-s", "--source", "--package-directory"}},
	{argv: []string{"nuget", "install"}, ecosystem: "nuget", manager: "nuget",
		valueFlags: []string{"-Version", "-OutputDirectory", "-Source", "-ConfigFile"}},

	// ── JVM ─────────────────────────────────────────────────────────────────
	{argv: []string{"mvn", "dependency:get"}, ecosystem: "maven", manager: "maven",
		valueFlags: []string{"-DrepoUrl"}},

	// ── Elixir ──────────────────────────────────────────────────────────────
	{argv: []string{"mix", "hex.package", "fetch"}, ecosystem: "hex", manager: "mix"},

	// ── Swift ───────────────────────────────────────────────────────────────
	{argv: []string{"swift", "package", "add-dependency"}, ecosystem: "swift", manager: "swift",
		valueFlags: []string{"--from", "--exact", "--branch", "--revision", "--up-to-next-minor-from"}},
}

// ParseInstallCommand recovers the packages a shell command would add.
//
// Returns nil for anything that is not adding a named dependency, which is the
// overwhelmingly common case and must stay silent: a bare `npm install`
// reinstalls a manifest that is already committed, `pip install -r req.txt` is
// the same, and a git or filesystem spec is not a registry package this can say
// anything about.
//
// The command is scanned in segments, so `cd web && npm i axios` and
// `NODE_ENV=x npm i axios && npm run build` both resolve.
func ParseInstallCommand(command string) []Candidate {
	var out []Candidate
	seen := map[string]bool{}

	for _, segment := range splitSegments(command) {
		for _, c := range parseSegment(segment) {
			key := c.Ecosystem + "\x00" + strings.ToLower(c.Name) + "\x00" + c.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, c)
		}
	}
	return out
}

// splitSegments breaks a command line on the operators that separate one
// command from the next. Quoted text is left alone so a separator inside a
// version constraint or a message does not split the line.
func splitSegments(command string) []string {
	var segments []string
	var cur strings.Builder
	var quote rune

	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			segments = append(segments, s)
		}
		cur.Reset()
	}

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if quote != 0 {
			cur.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			cur.WriteRune(r)
			continue
		case ';', '\n', '|':
			flush()
			// Skip the second character of "||".
			if r == '|' && i+1 < len(runes) && runes[i+1] == '|' {
				i++
			}
			continue
		case '&':
			if i+1 < len(runes) && runes[i+1] == '&' {
				flush()
				i++
				continue
			}
			flush()
			continue
		}
		cur.WriteRune(r)
	}
	flush()
	return segments
}

// parseSegment resolves one command, or returns nil when it adds nothing.
func parseSegment(segment string) []Candidate {
	tokens := tokenise(segment)
	tokens = stripEnvAssignments(tokens)
	tokens = normaliseInterpreter(tokens)
	if len(tokens) == 0 {
		return nil
	}

	// A global install puts a tool on the machine rather than a dependency in
	// this project. Nothing it does shows up in a manifest, so reporting on it
	// is a comment about the developer's toolbox, not about the software being
	// built.
	if hasGlobalFlag(tokens) {
		return nil
	}

	verb, rest, ok := matchVerb(tokens)
	if !ok {
		return nil
	}

	// `dotnet add [project] package <name>` needs the keyword to anchor, since
	// `dotnet add reference` is a different command entirely.
	if verb.manager == "dotnet" {
		idx := indexOf(rest, "package")
		if idx < 0 {
			return nil
		}
		rest = rest[idx+1:]
	}

	names := positionalArgs(rest, verb.valueFlags)

	out := make([]Candidate, 0, len(names))
	for _, raw := range names {
		c, ok := candidateFrom(raw, verb)
		if !ok {
			continue
		}
		out = append(out, c)
	}
	return out
}

// preSubcommandValueFlags are flags that can sit between a package manager and
// its subcommand and consume the next token.
//
// `npm --prefix ./web install axios` and `yarn --cwd web add axios` are both
// ordinary spellings, and matching only on adjacent tokens misses them
// entirely — which is a silent miss, the worst kind for a guard.
var preSubcommandValueFlags = map[string]bool{
	"--prefix": true, "--cwd": true, "-c": true, "--dir": true,
	"--config": true, "--registry": true, "-w": true, "--workspace": true,
	"--filter": true, "-f": true, "--project": true, "-p": true,
}

// matchVerb finds the longest install verb the tokens begin with, allowing
// flags between the binary and its subcommand.
//
// Returns the verb and everything after the subcommand. Flags skipped on the
// way are dropped: they configure where the install happens, not what is
// installed.
func matchVerb(tokens []string) (installVerb, []string, bool) {
	best := -1
	bestEnd := 0
	bestLen := 0

	for i, v := range installVerbs {
		if len(v.argv) <= bestLen || len(tokens) == 0 {
			continue
		}
		if !strings.EqualFold(basename(tokens[0]), v.argv[0]) {
			continue
		}

		pos := 1
		matched := true
		for _, want := range v.argv[1:] {
			// Skip any flags sitting between the binary and this word.
			for pos < len(tokens) && strings.HasPrefix(tokens[pos], "-") {
				flag := strings.ToLower(tokens[pos])
				pos++
				if !strings.Contains(flag, "=") && preSubcommandValueFlags[flag] && pos < len(tokens) {
					pos++
				}
			}
			if pos >= len(tokens) || !strings.EqualFold(basename(tokens[pos]), want) {
				matched = false
				break
			}
			pos++
		}
		if matched {
			best = i
			bestEnd = pos
			bestLen = len(v.argv)
		}
	}

	if best < 0 {
		return installVerb{}, nil, false
	}
	return installVerbs[best], tokens[bestEnd:], true
}

// normaliseInterpreter rewrites `python -m pip` and friends to the tool they
// run, so the verb table does not need an entry per interpreter.
func normaliseInterpreter(tokens []string) []string {
	if len(tokens) < 3 || tokens[1] != "-m" {
		return tokens
	}
	switch basename(tokens[0]) {
	case "python", "python3", "py", "python2":
	default:
		return tokens
	}
	switch strings.ToLower(tokens[2]) {
	case "pip", "uv", "pdm", "poetry", "pipenv":
		return append([]string{tokens[2]}, tokens[3:]...)
	}
	return tokens
}

// hasGlobalFlag reports whether a command installs into the machine rather than
// into this project.
func hasGlobalFlag(tokens []string) bool {
	for _, t := range tokens {
		switch strings.ToLower(t) {
		case "-g", "--global", "--location=global":
			return true
		}
	}
	return false
}

// positionalArgs drops flags and the values they consume, leaving the package
// names.
func positionalArgs(tokens []string, valueFlags []string) []string {
	takesValue := map[string]bool{}
	for _, f := range valueFlags {
		takesValue[strings.ToLower(f)] = true
	}

	var out []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if t == "--" {
			// Everything after "--" is positional by definition.
			out = append(out, tokens[i+1:]...)
			break
		}
		if strings.HasPrefix(t, "-") {
			// `--flag=value` carries its value, so it consumes nothing further.
			if strings.Contains(t, "=") {
				continue
			}
			if takesValue[strings.ToLower(t)] && i+1 < len(tokens) {
				i++
			}
			continue
		}
		out = append(out, t)
	}
	return out
}

// candidateFrom turns one positional argument into a package, or reports that
// it does not name a registry package.
func candidateFrom(raw string, verb installVerb) (Candidate, bool) {
	spec := strings.TrimSpace(unquote(raw))
	if spec == "" || !isRegistrySpec(spec) {
		return Candidate{}, false
	}

	name, version := spec, ""

	switch verb.ecosystem {
	case "pypi":
		name, version = splitPythonSpec(spec)
	case "golang":
		// A module path contains slashes and may contain "@" only as the
		// version separator, which is always the last one.
		if at := strings.LastIndex(spec, "@"); at > 0 {
			name, version = spec[:at], spec[at+1:]
		}
	case "maven":
		// group:artifact:version
		if parts := strings.Split(spec, ":"); len(parts) >= 2 {
			name = parts[0] + ":" + parts[1]
			if len(parts) >= 3 {
				version = parts[2]
			}
		}
	default:
		switch verb.separator {
		case "@":
			// A leading "@" is an npm scope, not a separator, so the search for
			// the separator starts past it.
			search := spec
			offset := 0
			if strings.HasPrefix(spec, "@") {
				search = spec[1:]
				offset = 1
			}
			if at := strings.Index(search, "@"); at >= 0 {
				name = spec[:offset+at]
				version = spec[offset+at+1:]
			}
		case ":":
			if c := strings.Index(spec, ":"); c > 0 {
				name, version = spec[:c], spec[c+1:]
			}
		}
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return Candidate{}, false
	}

	return Candidate{
		Name:      name,
		Version:   strings.TrimSpace(version),
		Ecosystem: verb.ecosystem,
		Manager:   verb.manager,
	}, true
}

// pythonOperators are the comparison operators PEP 508 allows, longest first so
// ">=" is found before ">".
var pythonOperators = []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<", "@"}

// splitPythonSpec separates a requirement from its constraint, discarding
// extras.
//
// `requests[security]>=2.0` names requests. The extras change what is
// installed alongside it but not which package is being added, and VDB is asked
// about the package.
func splitPythonSpec(spec string) (string, string) {
	name, version := spec, ""
	for _, op := range pythonOperators {
		if i := strings.Index(spec, op); i > 0 {
			name = spec[:i]
			version = strings.TrimSpace(spec[i+len(op):])
			// A comma introduces a second constraint; the first bound is the one
			// worth reporting and the resolver decides the rest.
			if c := strings.Index(version, ","); c >= 0 {
				version = version[:c]
			}
			break
		}
	}
	if b := strings.Index(name, "["); b > 0 {
		name = name[:b]
	}
	return strings.TrimSpace(name), strings.TrimSpace(version)
}

// isRegistrySpec rejects the arguments that are paths, URLs or source-control
// references rather than registry packages.
//
// Reporting on these would be worse than silence: nothing is known about them,
// and a guard that fires on `pip install -e .` teaches people to ignore it.
func isRegistrySpec(spec string) bool {
	lower := strings.ToLower(spec)
	switch {
	case spec == ".", spec == "..":
		return false
	case strings.HasPrefix(spec, "./"), strings.HasPrefix(spec, "../"),
		strings.HasPrefix(spec, "/"), strings.HasPrefix(spec, "~"):
		return false
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"),
		strings.HasPrefix(lower, "git+"), strings.HasPrefix(lower, "git@"),
		strings.HasPrefix(lower, "file:"), strings.HasPrefix(lower, "ssh://"):
		return false
	case strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".tar.gz"),
		strings.HasSuffix(lower, ".whl"), strings.HasSuffix(lower, ".zip"),
		strings.HasSuffix(lower, ".gem"), strings.HasSuffix(lower, ".nupkg"):
		return false
	}
	// A bare `go get ./...` or a glob is not a package either.
	if strings.Contains(spec, "*") {
		return false
	}
	return true
}

// tokenise splits a command into shell-ish words, honouring quotes so a pinned
// constraint like 'requests>=2,<3' survives as one token.
func tokenise(segment string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	started := false

	flush := func() {
		if started {
			out = append(out, cur.String())
		}
		cur.Reset()
		started = false
	}

	for _, r := range segment {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			started = true
		case r == '\'' || r == '"':
			quote = r
			started = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	flush()
	return out
}

// stripEnvAssignments drops a `KEY=value` prefix so `NODE_ENV=x npm i axios`
// still matches. Only leading assignments are prefixes; a later one is an
// argument.
func stripEnvAssignments(tokens []string) []string {
	for len(tokens) > 0 && isEnvAssignment(tokens[0]) {
		tokens = tokens[1:]
	}
	// `sudo`, `env` and `command` wrap the real command without changing it.
	for len(tokens) > 0 {
		switch basename(tokens[0]) {
		case "sudo", "env", "command", "nice", "time", "exec":
			tokens = tokens[1:]
			for len(tokens) > 0 && isEnvAssignment(tokens[0]) {
				tokens = tokens[1:]
			}
			continue
		}
		break
	}
	return tokens
}

func isEnvAssignment(tok string) bool {
	i := strings.Index(tok, "=")
	if i <= 0 || strings.HasPrefix(tok, "-") {
		return false
	}
	for _, r := range tok[:i] {
		if r != '_' && !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// basename strips a directory prefix so `/usr/local/bin/npm` matches `npm`.
func basename(tok string) string {
	if i := strings.LastIndexAny(tok, "/\\"); i >= 0 {
		return tok[i+1:]
	}
	return tok
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func indexOf(tokens []string, want string) int {
	for i, t := range tokens {
		if strings.EqualFold(t, want) {
			return i
		}
	}
	return -1
}

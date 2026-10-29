// Package dockerfrom reads the structure of a Dockerfile that container
// curation needs: each stage's FROM (as written and with ARG defaults applied),
// which stage is the final one, and the package-manager install lines in each
// stage's RUN instructions, with their line numbers.
//
// It is not a Dockerfile interpreter. Build arguments passed on the command line
// are unknown, so a FROM that depends on an ARG without a default is reported
// as unresolved rather than guessed.
package dockerfrom

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// Stage is one FROM and what follows it until the next.
type Stage struct {
	Index int
	// Name is the AS alias, lowercased as Docker treats it.
	Name   string
	Line   int
	RawRef string
	// ResolvedRef has ARG defaults applied; empty when the stage starts from an
	// earlier stage or an ARG has no default.
	ResolvedRef    string
	FromStage      string
	Platform       string
	IsFinal        bool
	UnresolvedArgs bool
	Installs       []Install
}

// Install is one package-manager install command.
type Install struct {
	Line     int
	Manager  string
	Packages []Package
}

// Package is a package as the command wrote it.
type Package struct {
	Name string
	// Spec is the argument as written (curl=8.5.0-r0) when it pins a version.
	Spec string
}

type instruction struct {
	line    int
	keyword string
	args    string
}

// Parse reads a Dockerfile.
func Parse(r io.Reader) []Stage {
	ins := instructions(r)
	globalArgs := map[string]string{}
	var stages []Stage
	stageArgs := map[string]string{}
	names := map[string]bool{}
	for _, in := range ins {
		// ARG is the only instruction a Dockerfile may have before its first
		// FROM. Anything else means the file only has a Dockerfile's name
		// (dockerfile.go, whose struct field "From string" would otherwise
		// read as FROM string), so it declares no image.
		if len(stages) == 0 && in.keyword != "ARG" && in.keyword != "FROM" {
			return nil
		}
		switch in.keyword {
		case "ARG":
			name, def, hasDef := strings.Cut(strings.TrimSpace(in.args), "=")
			name = strings.TrimSpace(name)
			if len(stages) == 0 {
				if hasDef {
					globalArgs[name] = unquote(def)
				} else if _, ok := globalArgs[name]; !ok {
					globalArgs[name] = ""
				}
			} else if hasDef {
				stageArgs[name] = unquote(def)
			}
		case "FROM":
			s := parseFrom(in, len(stages), globalArgs, names)
			stages = append(stages, s)
			if s.Name != "" {
				names[s.Name] = true
			}
			stageArgs = map[string]string{}
		case "RUN":
			if len(stages) == 0 {
				continue
			}
			vars := merge(globalArgs, stageArgs)
			cur := &stages[len(stages)-1]
			cur.Installs = append(cur.Installs, parseInstalls(in.line, expand(in.args, vars))...)
		}
	}
	if len(stages) > 0 {
		stages[len(stages)-1].IsFinal = true
	}
	return stages
}

func merge(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func parseFrom(in instruction, index int, args map[string]string, names map[string]bool) Stage {
	s := Stage{Index: index, Line: in.line, RawRef: strings.TrimSpace(in.args)}
	fields := strings.Fields(in.args)
	var ref string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case strings.HasPrefix(f, "--platform="):
			s.Platform = strings.TrimPrefix(f, "--platform=")
		case strings.HasPrefix(f, "--"):
		case strings.EqualFold(f, "as") && i+1 < len(fields):
			s.Name = strings.ToLower(fields[i+1])
			i++
		case ref == "":
			ref = f
		}
	}
	s.RawRef = ref
	if names[strings.ToLower(ref)] {
		s.FromStage = strings.ToLower(ref)
		return s
	}
	resolved, ok := expandStrict(ref, args)
	if !ok {
		s.UnresolvedArgs = true
		return s
	}
	if names[strings.ToLower(resolved)] {
		s.FromStage = strings.ToLower(resolved)
		return s
	}
	if strings.EqualFold(resolved, "scratch") {
		return s
	}
	s.ResolvedRef = resolved
	if p, ok := expandStrict(s.Platform, args); ok {
		s.Platform = p
	}
	return s
}

var varRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-+]([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expandStrict substitutes $VAR, ${VAR} and ${VAR:-default}; ok is false when a
// variable has neither a value nor a default.
func expandStrict(s string, vars map[string]string) (string, bool) {
	ok := true
	out := varRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := varRE.FindStringSubmatch(m)
		name := sub[1]
		if name == "" {
			name = sub[3]
		}
		if v := vars[name]; v != "" {
			return v
		}
		if strings.Contains(m, ":-") || strings.Contains(m, "-") && sub[2] != "" {
			return sub[2]
		}
		ok = false
		return m
	})
	return out, ok
}

func expand(s string, vars map[string]string) string {
	out, _ := expandStrict(s, vars)
	return out
}

// instructions joins continuation lines and drops comments, keeping the line
// each instruction starts on.
func instructions(r io.Reader) []instruction {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []instruction
	var cur strings.Builder
	start, n := 0, 0
	flush := func() {
		text := strings.TrimSpace(cur.String())
		cur.Reset()
		if text == "" {
			return
		}
		kw, args, _ := strings.Cut(text, " ")
		out = append(out, instruction{line: start, keyword: strings.ToUpper(kw), args: strings.TrimSpace(args)})
	}
	for sc.Scan() {
		n++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if cur.Len() == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			start = n
		} else if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, "\\") {
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(trimmed)
		flush()
	}
	flush()
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// installCommands maps a command prefix to its manager and the subcommands
// that install.
var installCommands = []struct {
	cmd, manager string
	subs         []string
}{
	{"apk", "apk", []string{"add"}},
	{"apt-get", "apt", []string{"install"}},
	{"apt", "apt", []string{"install"}},
	{"microdnf", "microdnf", []string{"install"}},
	{"dnf", "dnf", []string{"install"}},
	{"yum", "yum", []string{"install"}},
	{"tdnf", "dnf", []string{"install"}},
	{"zypper", "zypper", []string{"install", "in"}},
	{"pacman", "pacman", []string{"-S", "-Sy", "-Syu", "-Syy", "--sync"}},
}

// parseInstalls finds install commands in a RUN's shell text.
func parseInstalls(line int, run string) []Install {
	var out []Install
	for _, cmd := range splitShell(run) {
		fields := strings.Fields(cmd)
		for len(fields) > 0 && (fields[0] == "sudo" || strings.Contains(fields[0], "=") && !strings.HasPrefix(fields[0], "-")) {
			fields = fields[1:]
		}
		if len(fields) < 2 {
			continue
		}
		for _, ic := range installCommands {
			if fields[0] != ic.cmd && !strings.HasSuffix(fields[0], "/"+ic.cmd) {
				continue
			}
			sub := -1
			for i, f := range fields[1:] {
				for _, s := range ic.subs {
					if f == s {
						sub = i + 1
					}
				}
				if sub >= 0 {
					break
				}
			}
			if sub < 0 {
				break
			}
			in := Install{Line: line, Manager: ic.manager}
			skipNext := false
			for _, f := range fields[sub+1:] {
				if skipNext {
					skipNext = false
					continue
				}
				if strings.HasPrefix(f, "-") {
					// Options that take a separate value.
					switch f {
					case "-t", "--target-release", "-o", "--repo", "--enablerepo", "--disablerepo", "-X", "--repository", "--virtual":
						skipNext = true
					}
					continue
				}
				if strings.ContainsAny(f, "$`") || f == "\\" {
					continue
				}
				in.Packages = append(in.Packages, packageFrom(ic.manager, f))
			}
			if len(in.Packages) > 0 {
				out = append(out, in)
			}
			break
		}
	}
	return out
}

// packageFrom splits a pinned argument into its name, keeping the argument as
// the spec: apk name=1.2-r0 / name>1.2, apt name=1.2, pacman name=1.2; dnf and
// yum pins (name-1.2) cannot be split without the repository, so the name is
// the argument.
func packageFrom(manager, arg string) Package {
	switch manager {
	case "apk", "apt", "pacman", "zypper":
		if i := strings.IndexAny(arg, "=<>~"); i > 0 {
			return Package{Name: arg[:i], Spec: arg}
		}
	}
	return Package{Name: arg}
}

// splitShell splits on &&, ||, ; and |, outside quotes.
func splitShell(s string) []string {
	var out []string
	var cur strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			cur.WriteByte(c)
		case ';', '|', '&':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

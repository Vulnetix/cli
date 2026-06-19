package fix

import "strings"

func commandFor(p FixCandidate, target string) string {
	name := p.PackageName
	if p.Method == MethodParentUpgrade && p.ParentName != "" {
		// A parent-upgrade installs the PARENT at its resolved version, not the
		// vulnerable child at its safe version — use ParentName + ParentTarget for
		// every ecosystem (npm has its own helper below).
		name = p.ParentName
		target = p.ParentTarget
	}
	switch strings.ToLower(p.Ecosystem) {
	case "npm":
		if p.Method == MethodParentUpdate && p.ParentName != "" {
			return npmTransitiveCommand(MethodParentUpdate, p.ParentName, "")
		}
		if p.Method == MethodParentUpgrade && p.ParentName != "" {
			return npmTransitiveCommand(MethodParentUpgrade, p.ParentName, p.ParentTarget)
		}
		// Direct bumps and overrides both edit package.json; the install just
		// re-resolves the lockfile (never install the child as a direct dep).
		if p.Method == MethodDirectBump || p.Method == MethodOverride {
			return "npm install"
		}
		if target != "" {
			return "npm install " + name + "@" + target
		}
		return "npm install " + name
	case "pypi":
		return "pip install -r " + p.SourceFile
	case "golang":
		if target != "" {
			return "go get " + name + "@v" + target + " && go mod tidy"
		}
		return "go get " + name + " && go mod tidy"
	case "cargo":
		if target != "" {
			return "cargo update -p " + name + " --precise " + target
		}
		return "cargo update -p " + name
	case "rubygems":
		return "bundle update " + name + " --conservative"
	case "composer":
		return "composer update " + name + " --with-dependencies"
	case "maven":
		return "mvn -q -DskipTests dependency:resolve"
	default:
		if target != "" {
			return name + "@" + target
		}
		return name
	}
}

// goInstallSpec returns the `module@vVERSION` (or bare module) argument for one Go
// fix candidate, mirroring the golang branch of commandFor.
func goInstallSpec(p FixCandidate) string {
	name := p.PackageName
	target := p.TargetVer
	if p.Method == MethodParentUpgrade && p.ParentName != "" {
		name = p.ParentName
		target = p.ParentTarget
	}
	if name == "" {
		return ""
	}
	if target == "" {
		return name
	}
	return name + "@v" + target
}

// batchInstallCommand collapses all of a batch's non-skipped fixes into a single
// install command for ecosystems where that is safe and far faster than one
// command per fix. For Go, N per-fix `go get …@v && go mod tidy` invocations (each
// a full module re-resolution) become one `go get m1@v m2@v … && go mod tidy`.
// Returns ("", false) for ecosystems handled per-plan (npm already collapses to a
// single `npm install`, pypi to `pip install -r`).
func batchInstallCommand(b FixBatch) (string, bool) {
	if strings.ToLower(b.Ecosystem) != "golang" {
		return "", false
	}
	seen := map[string]bool{}
	specs := make([]string, 0, len(b.Plans))
	for _, p := range b.Plans {
		if p.Skipped || p.TargetVer == "" {
			continue
		}
		s := goInstallSpec(p)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		specs = append(specs, s)
	}
	if len(specs) == 0 {
		return "", false
	}
	return "go get " + strings.Join(specs, " ") + " && go mod tidy", true
}

func npmTransitiveCommand(method FixMethod, parent, target string) string {
	if method == MethodParentUpdate {
		return "npm update " + parent
	}
	if target != "" {
		return "npm install " + parent + "@" + target
	}
	return "npm install " + parent + "@<safe-version>"
}

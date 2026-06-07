package fix

import "strings"

func commandFor(p FixCandidate, target string) string {
	name := p.PackageName
	if p.Method == MethodParentUpgrade && p.ParentName != "" {
		name = p.ParentName
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

func npmTransitiveCommand(method FixMethod, parent, target string) string {
	if method == MethodParentUpdate {
		return "npm update " + parent
	}
	if target != "" {
		return "npm install " + parent + "@" + target
	}
	return "npm install " + parent + "@<safe-version>"
}

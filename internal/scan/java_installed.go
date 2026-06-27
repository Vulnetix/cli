package scan

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func init() {
	gateRegistry["maven"] = gateSpec{
		gated: func(t string) bool {
			return t == "pom.xml" || t == "build.gradle" || t == "build.gradle.kts"
		},
		lockPresent: func(dir string) bool { return anySiblingExists(dir, []string{"gradle.lockfile"}) },
		// pom.xml/gradle coordinates are normally exact; only genuinely unpinned
		// (ranged) coords reach the resolver, which cannot determine the resolved
		// version offline → build-or-lock.
		fullyPinned: allVersionsPinned,
		resolve:     ResolveJavaFromInstalled,
	}
}

// javaKey: Maven coordinates are "group:artifact" (case-sensitive).
func javaKey(n string) string { return n }

func javaBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has unpinned dependencies and no lock file: pin exact versions, add a gradle.lockfile (gradle dependencies --write-locks), or build the app, then re-run the scan", relPath)
}

// ResolveJavaFromInstalled resolves declared "group:artifact" coordinates against
// the global Maven (~/.m2) and Gradle (~/.gradle) caches (declared-only — these
// caches are shared across all projects, so transitives are never enumerated).
func ResolveJavaFromInstalled(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	home := homeDir()
	if home == "" {
		return nil, errors.New(javaBuildOrLockHint(relPath))
	}
	m2 := filepath.Join(home, ".m2", "repository")
	gradle := filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1")

	installed := map[string]installedDep{}
	for _, p := range declared {
		group, artifact, ok := splitMavenCoord(p.Name)
		if !ok {
			continue
		}
		// Maven: group dots → path segments.
		m2Base := filepath.Join(m2, filepath.Join(strings.Split(group, ".")...), artifact)
		if ver, dir, found := resolveNestedVersion(m2Base, p.Version); found {
			installed[javaKey(p.Name)] = installedDep{Name: p.Name, Version: ver, Dir: dir}
			continue
		}
		// Gradle: group kept literal.
		gradleBase := filepath.Join(gradle, group, artifact)
		if ver, dir, found := resolveNestedVersion(gradleBase, p.Version); found {
			installed[javaKey(p.Name)] = installedDep{Name: p.Name, Version: ver, Dir: dir}
		}
	}
	if len(installed) == 0 {
		return nil, errors.New(javaBuildOrLockHint(relPath))
	}
	return resolveFromGlobalInstall(relPath, "maven", declared, installed, javaKey, strict, javaBuildOrLockHint)
}

// splitMavenCoord splits "group:artifact" (ignoring any trailing :version).
func splitMavenCoord(coord string) (group, artifact string, ok bool) {
	parts := strings.Split(coord, ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

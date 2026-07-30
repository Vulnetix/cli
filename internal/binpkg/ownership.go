package binpkg

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Owner identifies the OS package that installed a file inside a container root
// filesystem.
type Owner struct {
	Name      string
	Version   string
	Ecosystem string // deb, apk or arch
	// Source is the package-database file the attribution came from, relative to
	// the container root.
	Source string
}

// Key is the "name@version" identity used to line the owner up with the package
// component parsed out of the same package database.
func (o Owner) Key() string { return o.Name + "@" + o.Version }

// OwnerIndex maps an absolute in-container path ("/usr/bin/curl") to the package
// that installed it. Paths are stored slash-separated and rooted, exactly as the
// package databases record them.
type OwnerIndex map[string]Owner

// Lookup resolves a path on the host (inside the extracted root) back to its
// owning package. root is the container root filesystem directory.
func (idx OwnerIndex) Lookup(root, hostPath string) (Owner, bool) {
	if len(idx) == 0 {
		return Owner{}, false
	}
	rel, err := filepath.Rel(root, hostPath)
	if err != nil {
		return Owner{}, false
	}
	owner, ok := idx["/"+filepath.ToSlash(rel)]
	return owner, ok
}

// BuildOwnerIndex reads the file lists of every package database present under a
// container root filesystem: dpkg (`var/lib/dpkg/info/*.list`), apk
// (`lib/apk/db/installed` F:/R: records) and pacman
// (`var/lib/pacman/local/*/files`).
//
// RPM is intentionally absent: its database is a Berkeley DB or SQLite file that
// cannot be read without linking a native library, so rpm-based images get
// package components (from the `sca` container pass) without per-file
// attribution. Callers should not treat a missing owner as "unpackaged" for those
// images — see HasFileOwnership.
func BuildOwnerIndex(root string) OwnerIndex {
	idx := OwnerIndex{}
	addDpkgOwners(root, idx)
	addAPKOwners(root, idx)
	addPacmanOwners(root, idx)
	return idx
}

// HasFileOwnership reports whether the root filesystem carries any package
// database whose file lists this package can read. It is false for rpm-only
// images and for arbitrary directories, which is the signal callers need before
// concluding a binary belongs to no package.
func HasFileOwnership(root string) bool {
	for _, probe := range []string{
		"var/lib/dpkg/info",
		"lib/apk/db/installed",
		"var/lib/apk/db/installed",
		"var/lib/pacman/local",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(probe))); err == nil {
			return true
		}
	}
	return false
}

// ── dpkg ────────────────────────────────────────────────────────────────────

func addDpkgOwners(root string, idx OwnerIndex) {
	infoDir := filepath.Join(root, filepath.FromSlash("var/lib/dpkg/info"))
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return
	}
	versions := dpkgVersions(root)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".list") {
			continue
		}
		// "libssl3:amd64.list" — the architecture qualifier is not part of the
		// package name recorded in var/lib/dpkg/status.
		name := strings.TrimSuffix(e.Name(), ".list")
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i]
		}
		owner := Owner{
			Name: name, Version: versions[name], Ecosystem: "deb",
			Source: "var/lib/dpkg/info/" + e.Name(),
		}
		eachLine(filepath.Join(infoDir, e.Name()), func(line string) {
			if path := normalizeOwnedPath(line); path != "" {
				idx.put(path, owner)
			}
		})
	}
}

// dpkgVersions reads name→version from the dpkg status file so an ownership hit
// can be matched to the package component parsed from the same file.
func dpkgVersions(root string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash("var/lib/dpkg/status")))
	if err != nil {
		return out
	}
	var name, version string
	flush := func() {
		if name != "" {
			out[name] = version
		}
		name, version = "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.TrimSpace(line) == "":
			flush()
		case strings.HasPrefix(line, "Package:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Version:"):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	flush()
	return out
}

// ── apk ─────────────────────────────────────────────────────────────────────

// addAPKOwners walks the apk installed database. Its file records are stateful:
// `F:` opens a directory, and each following `R:` names a file inside it.
func addAPKOwners(root string, idx OwnerIndex) {
	for _, rel := range []string{"lib/apk/db/installed", "var/lib/apk/db/installed"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		var name, version, dir string
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) < 2 || line[1] != ':' {
				if strings.TrimSpace(line) == "" {
					name, version, dir = "", "", ""
				}
				continue
			}
			value := strings.TrimSpace(line[2:])
			switch line[0] {
			case 'P':
				name, dir = value, ""
			case 'V':
				version = value
			case 'F':
				dir = strings.Trim(value, "/")
			case 'R':
				if name == "" || value == "" {
					continue
				}
				full := "/" + value
				if dir != "" {
					full = "/" + dir + "/" + value
				}
				idx.put(full, Owner{Name: name, Version: version, Ecosystem: "apk", Source: rel})
			}
		}
		_ = f.Close()
	}
}

// ── pacman ──────────────────────────────────────────────────────────────────

func addPacmanOwners(root string, idx OwnerIndex) {
	localDir := filepath.Join(root, filepath.FromSlash("var/lib/pacman/local"))
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name, version := splitPacmanDir(e.Name())
		if name == "" {
			continue
		}
		owner := Owner{
			Name: name, Version: version, Ecosystem: "arch",
			Source: "var/lib/pacman/local/" + e.Name() + "/files",
		}
		inFiles := false
		eachLine(filepath.Join(localDir, e.Name(), "files"), func(line string) {
			switch {
			case line == "%FILES%":
				inFiles = true
			case strings.HasPrefix(line, "%"):
				inFiles = false
			case inFiles:
				if strings.HasSuffix(line, "/") {
					return // directory entry
				}
				if path := normalizeOwnedPath("/" + line); path != "" {
					idx.put(path, owner)
				}
			}
		})
	}
}

// splitPacmanDir splits "openssl-3.2.1-1" into name and version. pacman uses the
// same "name-version-release" layout as its package files, so the split is on the
// last two hyphen-separated fields.
func splitPacmanDir(dir string) (string, string) {
	parts := strings.Split(dir, "-")
	if len(parts) < 3 {
		return dir, ""
	}
	return strings.Join(parts[:len(parts)-2], "-"), strings.Join(parts[len(parts)-2:], "-")
}

// ── shared helpers ──────────────────────────────────────────────────────────

func (idx OwnerIndex) put(path string, owner Owner) {
	// First writer wins: on the rare shared path, the earlier package keeps the
	// attribution rather than the alphabetically-later one silently replacing it.
	if _, exists := idx[path]; !exists {
		idx[path] = owner
	}
}

func normalizeOwnedPath(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || line == "/." || line == "/" {
		return ""
	}
	if !strings.HasPrefix(line, "/") {
		line = "/" + line
	}
	return strings.TrimSuffix(filepath.ToSlash(line), "/")
}

func eachLine(path string, visit func(string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		visit(strings.TrimRight(scanner.Text(), "\r"))
	}
}

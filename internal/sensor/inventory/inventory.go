// Package inventory answers which installed packages are actually in use on a
// host, from what running processes have mapped into memory.
//
// Three states matter, and installed-only is not one a scanner can tell apart
// from the other two:
//
//   - loaded: a running process maps a file the package installed, so a
//     vulnerability in it is reachable from a live process.
//   - stale-loaded: a process maps a file that has since been replaced or
//     deleted on disk ("(deleted)" in its maps). The package on disk may be
//     fixed while the process still runs the old code; it needs a restart,
//     and a disk scan reports it as fixed.
//   - neither: installed and not mapped by anything right now.
//
// Mappings of anonymous memory files (memfd:) with execute permission are
// reported separately: code run from a memfd never touches the filesystem,
// which is how fileless malware avoids a disk scan. JIT runtimes and browsers
// do it too, so the list is a lead to check, not a verdict.
package inventory

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vulnetix/cli/v3/internal/binpkg"
)

// States.
const (
	Loaded      = "loaded"
	StaleLoaded = "stale-loaded"
)

const listCap = 10

// Process is one running process.
type Process struct {
	PID int    `json:"pid"`
	Exe string `json:"exe,omitempty"`
}

// Package is one package some process maps.
type Package struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem string    `json:"ecosystem"`
	State     string    `json:"state"`
	Processes []Process `json:"processes"`
	Files     []string  `json:"files"`
}

// Result is one scan.
type Result struct {
	Packages []Package `json:"packages"`
	// Unowned are executable files mapped by a process that no package
	// installed, at most 50.
	Unowned []string `json:"unowned,omitempty"`
	// MemfdExec are processes running code mapped from an anonymous memory
	// file.
	MemfdExec []Process `json:"memfdExec,omitempty"`
	Processes int       `json:"processes"`
	// Unreadable counts processes whose maps could not be read (another
	// user's, without the privilege to read them). A scan with many is
	// incomplete, and says so.
	Unreadable int `json:"unreadable"`
}

type pkgKey struct{ name, version, eco string }

// Scan reads root/proc. root is "/" on the host, or a mounted /proc's parent
// in tests. idx maps installed files to packages (binpkg.BuildOwnerIndex).
func Scan(root string, idx binpkg.OwnerIndex) Result {
	var res Result
	entries, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return res
	}

	pkgs := map[pkgKey]*Package{}
	unowned := map[string]bool{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		res.Processes++
		f, err := os.Open(filepath.Join(root, "proc", e.Name(), "maps"))
		if err != nil {
			res.Unreadable++

			continue
		}
		exe, _ := os.Readlink(filepath.Join(root, "proc", e.Name(), "exe"))
		proc := Process{PID: pid, Exe: strings.TrimSuffix(exe, " (deleted)")}

		memfd := false
		seenInProc := map[string]bool{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			path, perms, ok := mappedPath(sc.Text())
			if !ok {
				continue
			}
			if strings.HasPrefix(path, "/memfd:") {
				if strings.Contains(perms, "x") {
					memfd = true
				}

				continue
			}
			if !strings.HasPrefix(path, "/") || seenInProc[path] {
				continue
			}
			seenInProc[path] = true
			stale := strings.HasSuffix(path, " (deleted)")
			file := strings.TrimSuffix(path, " (deleted)")

			owner, owned := lookup(idx, file)
			if !owned {
				if strings.Contains(perms, "x") && !stale {
					unowned[file] = true
				}

				continue
			}
			k := pkgKey{owner.Name, owner.Version, owner.Ecosystem}
			p := pkgs[k]
			if p == nil {
				p = &Package{Name: owner.Name, Version: owner.Version, Ecosystem: owner.Ecosystem, State: Loaded}
				pkgs[k] = p
			}
			if stale {
				p.State = StaleLoaded
			}
			if len(p.Files) < listCap && !contains(p.Files, file) {
				p.Files = append(p.Files, file)
			}
			if len(p.Processes) < listCap && !hasPID(p.Processes, pid) {
				p.Processes = append(p.Processes, proc)
			}
		}
		_ = f.Close()
		if memfd {
			res.MemfdExec = append(res.MemfdExec, proc)
		}
	}

	for _, p := range pkgs {
		res.Packages = append(res.Packages, *p)
	}
	sort.Slice(res.Packages, func(i, j int) bool {
		a, b := res.Packages[i], res.Packages[j]
		if a.State != b.State {
			return a.State == StaleLoaded
		}

		return a.Name < b.Name
	})
	for path := range unowned {
		res.Unowned = append(res.Unowned, path)
	}
	sort.Strings(res.Unowned)
	if len(res.Unowned) > 50 {
		res.Unowned = res.Unowned[:50]
	}
	sort.Slice(res.MemfdExec, func(i, j int) bool { return res.MemfdExec[i].PID < res.MemfdExec[j].PID })

	return res
}

// mappedPath reads the pathname field of a /proc/<pid>/maps line:
// "7f1c... r-xp 00000000 fd:01 1234   /usr/lib/libssl.so.3 (deleted)".
// The path is everything after the fifth field and may contain spaces.
func mappedPath(line string) (path, perms string, ok bool) {
	fields := 0
	inField := false
	for i, r := range line {
		if r == ' ' || r == '\t' {
			inField = false

			continue
		}
		if !inField {
			inField = true
			fields++
			if fields == 2 {
				end := strings.IndexAny(line[i:], " \t")
				if end < 0 {
					return "", "", false
				}
				perms = line[i : i+end]
			}
			if fields == 6 {
				return strings.TrimSpace(line[i:]), perms, true
			}
		}
	}

	return "", "", false
}

// lookup finds the package that installed a file, trying the merged-/usr
// twin: a package may list /lib/x86_64-linux-gnu/libz.so.1 while the process
// maps /usr/lib/x86_64-linux-gnu/libz.so.1, which is the same file.
func lookup(idx binpkg.OwnerIndex, path string) (binpkg.Owner, bool) {
	if o, ok := idx[path]; ok {
		return o, true
	}
	for _, top := range []string{"/lib", "/lib64", "/bin", "/sbin"} {
		if strings.HasPrefix(path, "/usr"+top+"/") {
			if o, ok := idx[strings.TrimPrefix(path, "/usr")]; ok {
				return o, true
			}
		}
		if strings.HasPrefix(path, top+"/") {
			if o, ok := idx["/usr"+path]; ok {
				return o, true
			}
		}
	}

	return binpkg.Owner{}, false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}

	return false
}

func hasPID(list []Process, pid int) bool {
	for _, p := range list {
		if p.PID == pid {
			return true
		}
	}

	return false
}

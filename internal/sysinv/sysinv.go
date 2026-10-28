// Package sysinv reads the operating system's own record of what is installed
// under a root filesystem: the dpkg, apk, pacman and rpm package databases and
// /etc/os-release. The root is a live system ("/"), a mounted volume, an
// unpacked image or /proc/<pid>/root — every path is joined under it and none
// is followed out of it.
//
// It exists so that a distro package is named the way the distro's own security
// advisories name it. Amazon Linux, RHEL and Debian backport fixes without
// moving the upstream version, so "openssl 3.0.8" is affected upstream and fixed
// in 3.0.8-1.amzn2023.0.12. A match is only right when the purl carries the
// full distro version, the release it was built for (distro=amazon-2023) and,
// for Debian, the source package the advisory is filed against (upstream=).
package sysinv

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	// The pure-Go SQLite driver go-rpmdb opens rpmdb.sqlite through; it keeps
	// the CLI free of cgo.
	_ "github.com/glebarez/go-sqlite"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

// Distro is the part of os-release a package match depends on.
type Distro struct {
	ID         string   // os-release ID: debian, ubuntu, amzn, rhel, alpine, …
	IDLike     []string // os-release ID_LIKE
	VersionID  string   // os-release VERSION_ID: 12, 2023, 3.19.1, …
	PrettyName string
}

// Namespace is the purl namespace for this distro's packages, using the vendor
// names the advisory feeds and other scanners use rather than os-release's
// abbreviations: amzn is amazon, rhel is redhat, ol is oracle.
func (d Distro) Namespace() string {
	switch d.ID {
	case "amzn":
		return "amazon"
	case "rhel":
		return "redhat"
	case "ol":
		return "oracle"
	case "sles", "sled", "sle-micro":
		return "suse"
	case "opensuse-leap", "opensuse-tumbleweed", "opensuse":
		return "opensuse"
	case "rocky", "almalinux", "centos", "fedora", "debian", "ubuntu", "alpine", "arch", "wolfi", "chainguard", "photon", "mariner", "azurelinux":
		return d.ID
	}
	return d.ID
}

// Release is the purl distro qualifier: namespace-version, with Alpine cut to
// major.minor because its secdb is per branch (alpine-3.19, not alpine-3.19.1).
// Blank when os-release gives no version (Arch, Wolfi), so no qualifier is
// invented for a rolling release.
func (d Distro) Release() string {
	if d.ID == "" || d.VersionID == "" {
		return ""
	}
	v := d.VersionID
	if d.ID == "alpine" {
		if parts := strings.SplitN(v, ".", 3); len(parts) >= 2 {
			v = parts[0] + "." + parts[1]
		}
	}
	return d.Namespace() + "-" + v
}

// Package is one installed OS package.
type Package struct {
	Name string
	// Version is the version the distro's advisories compare against: dpkg's
	// Version field as written (epoch included), apk's V:, pacman's %VERSION%,
	// and for rpm version-release with the epoch carried separately.
	Version string
	// Epoch is rpm's epoch when the package declares one; nil otherwise.
	Epoch *int
	Arch  string
	// Ecosystem is deb, apk, arch or rpm.
	Ecosystem string
	// SourceName is the source package the binary package was built from
	// (dpkg Source, apk origin, pacman %BASE%, the rpm SRPM's name). Debian
	// and Alpine advisories name the source package, not the binary one.
	SourceName string
	License    string
	// DB is the package database the entry came from, relative to the root.
	DB string
	// Files lists the absolute in-root paths the package installed, when the
	// database records them (rpm). The dpkg, apk and pacman file lists are
	// read by binpkg directly.
	Files []string
}

// Purl renders the package URL with the qualifiers a distro advisory match
// needs. The layout follows the purl spec and what Syft and Trivy emit, so the
// same package is the same string across tools.
func (p Package) Purl(d Distro) string {
	ns := d.Namespace()
	if ns == "" {
		switch p.Ecosystem {
		case "apk":
			ns = "alpine"
		case "arch":
			ns = "arch"
		}
	}
	typ := p.Ecosystem
	if typ == "arch" {
		typ = "alpm"
	}
	q := url.Values{}
	if p.Arch != "" {
		q.Set("arch", p.Arch)
	}
	if p.Epoch != nil && *p.Epoch != 0 {
		q.Set("epoch", strconv.Itoa(*p.Epoch))
	}
	if r := d.Release(); r != "" {
		q.Set("distro", r)
	}
	if p.SourceName != "" && p.SourceName != p.Name {
		q.Set("upstream", p.SourceName)
	}
	var b strings.Builder
	b.WriteString("pkg:" + typ + "/")
	if ns != "" {
		b.WriteString(url.PathEscape(ns) + "/")
	}
	b.WriteString(url.PathEscape(p.Name))
	if p.Version != "" {
		b.WriteString("@" + url.PathEscape(p.Version))
	}
	if len(q) > 0 {
		// url.Values.Encode sorts by key, which the purl spec requires.
		b.WriteString("?" + q.Encode())
	}
	return b.String()
}

// Result is everything read from one root.
type Result struct {
	Distro   Distro
	Packages []Package
	// Warnings name databases that exist but could not be read. A system with
	// an unreadable rpmdb is not a system with no packages, and a caller must
	// not report it as one.
	Warnings []string
}

// Collect reads every package database present under root.
func Collect(root string) Result {
	res := Result{Distro: ReadOSRelease(root)}
	res.Packages = append(res.Packages, readDpkg(root)...)
	res.Packages = append(res.Packages, readAPK(root)...)
	res.Packages = append(res.Packages, readPacman(root)...)
	pkgs, warns := readRPM(root)
	res.Packages = append(res.Packages, pkgs...)
	res.Warnings = append(res.Warnings, warns...)
	return res
}

// ReadOSRelease parses etc/os-release, falling back to usr/lib/os-release as
// os-release(5) specifies.
func ReadOSRelease(root string) Distro {
	var d Distro
	for _, rel := range []string{"etc/os-release", "usr/lib/os-release"} {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok || strings.HasPrefix(k, "#") {
				continue
			}
			v = strings.Trim(v, `"'`)
			switch k {
			case "ID":
				d.ID = strings.ToLower(v)
			case "ID_LIKE":
				d.IDLike = strings.Fields(strings.ToLower(v))
			case "VERSION_ID":
				d.VersionID = v
			case "PRETTY_NAME":
				d.PrettyName = v
			}
		}
		_ = f.Close()
		if d.ID != "" {
			return d
		}
	}
	return d
}

// ── dpkg ────────────────────────────────────────────────────────────────────

// readDpkg reads var/lib/dpkg/status and, for distroless images that have no
// status file, the per-package files in var/lib/dpkg/status.d.
func readDpkg(root string) []Package {
	var out []Package
	const status = "var/lib/dpkg/status"
	if data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(status))); err == nil {
		out = append(out, parseDpkg(data, status)...)
	}
	matches, _ := filepath.Glob(filepath.Join(root, "var", "lib", "dpkg", "status.d", "*"))
	sort.Strings(matches)
	for _, m := range matches {
		if strings.HasSuffix(m, ".md5sums") {
			continue
		}
		if data, err := os.ReadFile(m); err == nil {
			out = append(out, parseDpkg(data, relSlash(root, m))...)
		}
	}
	return out
}

// parseDpkg parses dpkg control paragraphs. Only packages whose Status says
// they are installed count: a removed package leaves a "deinstall ok
// config-files" paragraph behind, and reporting its CVEs would be a false
// positive against software that is gone. status.d entries carry no Status
// line and are installed by construction.
func parseDpkg(data []byte, db string) []Package {
	var out []Package
	for _, block := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n") {
		f := controlFields(block)
		if f["Package"] == "" {
			continue
		}
		if st, ok := f["Status"]; ok && !strings.HasSuffix(st, " installed") {
			continue
		}
		src := f["Source"]
		// "Source: openssl (3.0.11-1)" names the source version when it
		// differs from the binary's; the name is what the advisory uses.
		if i := strings.IndexByte(src, ' '); i > 0 {
			src = src[:i]
		}
		out = append(out, Package{
			Name: f["Package"], Version: f["Version"], Arch: f["Architecture"],
			Ecosystem: "deb", SourceName: src, DB: db,
		})
	}
	return out
}

// controlFields parses one RFC 822-style control paragraph. Continuation lines
// (leading space) belong to the previous field and are not needed here.
func controlFields(block string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// ── apk ─────────────────────────────────────────────────────────────────────

func readAPK(root string) []Package {
	for _, rel := range []string{"lib/apk/db/installed", "var/lib/apk/db/installed"} {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		// Both paths are the same database on systems that keep the legacy
		// symlink; the first one read is the answer.
		return parseAPK(data, rel)
	}
	return nil
}

func parseAPK(data []byte, db string) []Package {
	var out []Package
	for _, block := range strings.Split(string(data), "\n\n") {
		var p Package
		for _, line := range strings.Split(block, "\n") {
			if len(line) < 2 || line[1] != ':' {
				continue
			}
			v := strings.TrimSpace(line[2:])
			switch line[0] {
			case 'P':
				p.Name = v
			case 'V':
				p.Version = v
			case 'A':
				p.Arch = v
			case 'o':
				p.SourceName = v
			case 'L':
				p.License = v
			}
		}
		if p.Name == "" {
			continue
		}
		p.Ecosystem, p.DB = "apk", db
		out = append(out, p)
	}
	return out
}

// ── pacman ──────────────────────────────────────────────────────────────────

func readPacman(root string) []Package {
	matches, _ := filepath.Glob(filepath.Join(root, "var", "lib", "pacman", "local", "*", "desc"))
	sort.Strings(matches)
	var out []Package
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		if p, ok := parsePacmanDesc(data, relSlash(root, m)); ok {
			out = append(out, p)
		}
	}
	return out
}

func parsePacmanDesc(data []byte, db string) (Package, bool) {
	p := Package{Ecosystem: "arch", DB: db}
	lines := strings.Split(string(data), "\n")
	for i := 0; i+1 < len(lines); i++ {
		v := strings.TrimSpace(lines[i+1])
		switch lines[i] {
		case "%NAME%":
			p.Name = v
		case "%VERSION%":
			p.Version = v
		case "%ARCH%":
			p.Arch = v
		case "%BASE%":
			p.SourceName = v
		case "%LICENSE%":
			p.License = v
		}
	}
	return p, p.Name != ""
}

// ── rpm ─────────────────────────────────────────────────────────────────────

// rpmDBPaths are the places an rpm database lives, newest layout first:
// SQLite (Fedora 33+, RHEL 9, Amazon Linux 2023), NDB (SUSE), and Berkeley DB
// (RHEL 7/8, Amazon Linux 2, CentOS). /usr/lib/sysimage/rpm is the post-2021
// location; /var/lib/rpm is often a symlink to it.
var rpmDBPaths = []string{
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/Packages.db",
	"usr/lib/sysimage/rpm/Packages",
	"var/lib/rpm/rpmdb.sqlite",
	"var/lib/rpm/Packages.db",
	"var/lib/rpm/Packages",
}

func readRPM(root string) ([]Package, []string) {
	var warnings []string
	for _, rel := range rpmDBPaths {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if info, err := os.Stat(full); err != nil || info.IsDir() {
			continue
		}
		infos, err := listRPM(full)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		out := make([]Package, 0, len(infos))
		for _, pi := range infos {
			// gpg-pubkey entries are imported signing keys, not software.
			if pi.Name == "gpg-pubkey" {
				continue
			}
			out = append(out, rpmPackage(pi, rel))
		}
		// One database per system; a sysimage path and its /var/lib/rpm
		// symlink are the same file.
		return out, nil
	}
	return nil, warnings
}

// listRPM opens an rpm database. SQLite needs to create its -shm/-wal side
// files next to the database, which a read-only mount or someone else's
// /proc/<pid>/root refuses, so a failed open is retried on a private copy.
func listRPM(path string) ([]*rpmdb.PackageInfo, error) {
	if infos, err := openAndList(path); err == nil {
		return infos, nil
	} else if !strings.HasSuffix(path, ".sqlite") {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vulnetix-rpmdb-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	dst := filepath.Join(dir, filepath.Base(path))
	if err := copyFile(path, dst); err != nil {
		return nil, err
	}
	// A database mid-transaction keeps recent rows in its WAL.
	_ = copyFile(path+"-wal", dst+"-wal")
	return openAndList(dst)
}

func openAndList(path string) ([]*rpmdb.PackageInfo, error) {
	db, err := rpmdb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return db.ListPackages()
}

func rpmPackage(pi *rpmdb.PackageInfo, db string) Package {
	version := pi.Version
	if pi.Release != "" {
		version += "-" + pi.Release
	}
	p := Package{
		Name: pi.Name, Version: version, Epoch: pi.Epoch, Arch: pi.Arch,
		Ecosystem: "rpm", SourceName: srpmName(pi.SourceRpm), License: pi.License, DB: db,
	}
	if files, err := pi.InstalledFileNames(); err == nil {
		p.Files = files
	}
	return p
}

// srpmName reduces "openssl-3.0.8-1.amzn2023.0.12.src.rpm" to "openssl": strip
// the suffix, then the last two hyphen fields (version and release).
func srpmName(srpm string) string {
	s := strings.TrimSuffix(srpm, ".rpm")
	s = strings.TrimSuffix(s, ".src")
	s = strings.TrimSuffix(s, ".nosrc")
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

// ── helpers ─────────────────────────────────────────────────────────────────

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func relSlash(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

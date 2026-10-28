package sysinv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byName(pkgs []Package) map[string]Package {
	out := map[string]Package{}
	for _, p := range pkgs {
		out[p.Name] = p
	}
	return out
}

func TestDebianStatusSkipsRemovedPackages(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n")
	write(t, root, "var/lib/dpkg/status", `Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.11-1~deb12u2)
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 continuation line: not a field

Package: oldtool
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1

Package: tzdata
Status: install ok installed
Architecture: all
Version: 2024a-0+deb12u1
`)

	res := Collect(root)
	got := byName(res.Packages)
	if _, ok := got["oldtool"]; ok {
		t.Fatal("a removed package (config-files only) must not be reported as installed")
	}
	ssl, ok := got["libssl3"]
	if !ok {
		t.Fatalf("libssl3 missing: %+v", res.Packages)
	}
	if want := "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl"; ssl.Purl(res.Distro) != want {
		t.Errorf("purl\n got %s\nwant %s", ssl.Purl(res.Distro), want)
	}
	// A binary package named after its source carries no upstream qualifier.
	if p := got["tzdata"].Purl(res.Distro); strings.Contains(p, "upstream=") {
		t.Errorf("tzdata purl has a redundant upstream: %s", p)
	}
}

func TestDistrolessStatusD(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/lib/dpkg/status.d/libc6", "Package: libc6\nVersion: 2.36-9+deb12u4\nArchitecture: amd64\nSource: glibc\n")
	write(t, root, "var/lib/dpkg/status.d/libc6.md5sums", "d41d8cd98f00b204e9800998ecf8427e  lib/x86_64-linux-gnu/libc.so.6\n")

	got := byName(Collect(root).Packages)
	if len(got) != 1 || got["libc6"].SourceName != "glibc" {
		t.Fatalf("status.d not read correctly: %+v", got)
	}
}

func TestAlpineRelease(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=alpine\nVERSION_ID=3.19.1\n")
	write(t, root, "lib/apk/db/installed", "C:Q1abc=\nP:libcrypto3\nV:3.1.4-r5\nA:x86_64\no:openssl\nL:Apache-2.0\n\nP:musl\nV:1.2.4_git20230717-r4\nA:x86_64\no:musl\n")

	res := Collect(root)
	got := byName(res.Packages)
	if want := "pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=x86_64&distro=alpine-3.19&upstream=openssl"; got["libcrypto3"].Purl(res.Distro) != want {
		t.Errorf("purl\n got %s\nwant %s", got["libcrypto3"].Purl(res.Distro), want)
	}
}

func TestPacman(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=arch\n")
	write(t, root, "var/lib/pacman/local/openssl-3.2.1-1/desc", "%NAME%\nopenssl\n\n%VERSION%\n3.2.1-1\n\n%BASE%\nopenssl\n\n%ARCH%\nx86_64\n")

	res := Collect(root)
	// Arch is rolling: no distro qualifier is invented.
	if want := "pkg:alpm/arch/openssl@3.2.1-1?arch=x86_64"; res.Packages[0].Purl(res.Distro) != want {
		t.Errorf("purl\n got %s\nwant %s", res.Packages[0].Purl(res.Distro), want)
	}
}

func TestAmazonLinuxNamespace(t *testing.T) {
	epoch := 1
	d := Distro{ID: "amzn", VersionID: "2023"}
	p := Package{Name: "openssl-libs", Version: "3.0.8-1.amzn2023.0.12", Epoch: &epoch, Arch: "x86_64", Ecosystem: "rpm", SourceName: "openssl"}
	if want := "pkg:rpm/amazon/openssl-libs@3.0.8-1.amzn2023.0.12?arch=x86_64&distro=amazon-2023&epoch=1&upstream=openssl"; p.Purl(d) != want {
		t.Errorf("purl\n got %s\nwant %s", p.Purl(d), want)
	}
}

func TestSrpmName(t *testing.T) {
	for in, want := range map[string]string{
		"openssl-3.0.8-1.amzn2023.0.12.src.rpm": "openssl",
		"python3-pip-21.3.1-2.el9.src.rpm":      "python3-pip",
		"":                                      "",
	} {
		if got := srpmName(in); got != want {
			t.Errorf("srpmName(%q) = %q, want %q", in, got, want)
		}
	}
}

// rpmFixture returns a fixture database shipped with go-rpmdb. They are several
// megabytes each, so they are read from the module cache rather than copied
// into this repository. The cache is read-only, which is also what makes the
// SQLite case exercise the copy-on-open fallback.
func rpmFixture(t *testing.T, rel string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/knqyf263/go-rpmdb").Output()
	if err != nil {
		t.Skipf("go-rpmdb module not available: %v", err)
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "pkg", "testdata", filepath.FromSlash(rel))
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s not present: %v", rel, err)
	}
	return p
}

func linkRPM(t *testing.T, fixture, dbRel string) string {
	t.Helper()
	root := t.TempDir()
	dst := filepath.Join(root, filepath.FromSlash(dbRel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fixture, dst); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRPMDatabases(t *testing.T) {
	cases := []struct {
		name, fixture, db, osRelease, wantPkg, wantDistro string
	}{
		{"sqlite", "fedora35/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite", "ID=fedora\nVERSION_ID=35\n", "bash", "fedora-35"},
		{"berkeley", "centos7-plain/Packages", "var/lib/rpm/Packages", "ID=\"centos\"\nVERSION_ID=\"7\"\n", "openssl-libs", "centos-7"},
		{"ndb", "sle15-bci/Packages.db", "usr/lib/sysimage/rpm/Packages.db", "ID=\"sles\"\nVERSION_ID=\"15.3\"\n", "bash", "suse-15.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := linkRPM(t, rpmFixture(t, tc.fixture), tc.db)
			write(t, root, "etc/os-release", tc.osRelease)

			res := Collect(root)
			if len(res.Warnings) > 0 {
				t.Fatalf("warnings: %v", res.Warnings)
			}
			got := byName(res.Packages)
			if _, ok := got["gpg-pubkey"]; ok {
				t.Error("gpg-pubkey is a signing key, not a package")
			}
			p, ok := got[tc.wantPkg]
			if !ok {
				t.Fatalf("%s missing from %d packages", tc.wantPkg, len(res.Packages))
			}
			if !strings.Contains(p.Version, "-") {
				t.Errorf("rpm version must carry the release: %q", p.Version)
			}
			purl := p.Purl(res.Distro)
			if !strings.HasPrefix(purl, "pkg:rpm/") || !strings.Contains(purl, "distro="+tc.wantDistro) {
				t.Errorf("purl %s", purl)
			}
			if len(p.Files) == 0 {
				t.Errorf("%s: no installed files read", tc.wantPkg)
			}
		})
	}
}

func TestUnreadableRPMIsAWarningNotAnEmptySystem(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/lib/rpm/rpmdb.sqlite", "not a database")
	res := Collect(root)
	if len(res.Warnings) == 0 {
		t.Fatal("an unreadable rpmdb must surface as a warning")
	}
}

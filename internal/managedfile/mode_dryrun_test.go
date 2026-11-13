package managedfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileMode(t *testing.T) {
	merge := func(s string) (string, error) { return s, nil }
	for _, tt := range []struct {
		name string
		f    File
		want Mode
	}{
		{"merge wins over structured", File{Merge: merge, Structured: true}, ModeMerge},
		{"merge", File{Merge: merge}, ModeMerge},
		{"structured", File{Structured: true}, ModeStructured},
		{"neither", File{}, ModeBlock},
	} {
		if got := tt.f.Mode(); got != tt.want {
			t.Errorf("%s: Mode() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestOwnsContent(t *testing.T) {
	const host = "packages.vulnetix.com"
	for _, tt := range []struct {
		name     string
		marker   string
		existing string
		host     string
		want     bool
	}{
		{"host alone", "", "url = https://packages.vulnetix.com/npm", host, true},
		{"marker alone", "# vulnetix-credentials", "# vulnetix-credentials\nsecret=x", host, true},
		{"marker without host argument", "# vulnetix-credentials", "# vulnetix-credentials", "", true},
		{"neither present", "# vulnetix-credentials", "registry=https://registry.npmjs.org", host, false},
		{"host and marker both empty", "", "anything at all", "", false},
	} {
		if got := (File{Marker: tt.marker}).ownsContent(tt.existing, tt.host); got != tt.want {
			t.Errorf("%s: ownsContent = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// dryRunRemove runs RemoveFile with dryRun and checks that neither the file
// nor its backup changed on disk.
func dryRunRemove(t *testing.T, f File, host string) RemoveOutcome {
	t.Helper()
	before, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	bakBefore, bakErr := os.ReadFile(f.Path + BackupSuffix)

	out, err := RemoveFile(f, pkgMarkers, host, true)
	if err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatalf("dry run removed the file: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("dry run rewrote the file:\n%q\n%q", before, after)
	}
	bakAfter, bakErrAfter := os.ReadFile(f.Path + BackupSuffix)
	if (bakErr == nil) != (bakErrAfter == nil) || string(bakBefore) != string(bakAfter) {
		t.Fatal("dry run changed the backup")
	}
	return out
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveFileDryRunReportsWithoutTouching(t *testing.T) {
	const host = "packages.vulnetix.com"
	dir := t.TempDir()

	t.Run("structured with backup is restored", func(t *testing.T) {
		p := filepath.Join(dir, "settings.xml")
		writeFile(t, p, "<mirror>https://packages.vulnetix.com</mirror>")
		writeFile(t, p+BackupSuffix, "<settings/>")
		out := dryRunRemove(t, File{Path: p, Structured: true}, host)
		if !out.Existed || !out.Configured || !out.Restored || out.Deleted || out.Stripped {
			t.Errorf("outcome = %+v", out)
		}
	})

	t.Run("structured of ours is deleted", func(t *testing.T) {
		p := filepath.Join(dir, "pip.conf")
		writeFile(t, p, "index-url = https://packages.vulnetix.com/pypi")
		out := dryRunRemove(t, File{Path: p, Structured: true}, host)
		if !out.Configured || !out.Deleted || out.Restored || out.Stripped {
			t.Errorf("outcome = %+v", out)
		}
	})

	t.Run("structured not ours is left", func(t *testing.T) {
		p := filepath.Join(dir, "other.conf")
		writeFile(t, p, "index-url = https://pypi.org/simple")
		out := dryRunRemove(t, File{Path: p, Structured: true}, host)
		if !out.Existed || out.Configured || out.Deleted {
			t.Errorf("outcome = %+v", out)
		}
	})

	t.Run("merge without backup is stripped", func(t *testing.T) {
		p := filepath.Join(dir, "settings.json")
		writeFile(t, p, `{"ours": true, "theirs": true}`)
		f := File{
			Path:  p,
			Merge: func(s string) (string, error) { return s, nil },
			Strip: func(_, existing string) (string, bool) {
				return strings.Replace(existing, `"ours": true, `, "", 1), true
			},
		}
		out := dryRunRemove(t, f, host)
		if out.Mode != ModeMerge || !out.Configured || !out.Stripped || out.Deleted || out.Restored {
			t.Errorf("outcome = %+v", out)
		}
	})

	t.Run("merge with nothing to strip", func(t *testing.T) {
		p := filepath.Join(dir, "plain.json")
		writeFile(t, p, `{"theirs": true}`)
		f := File{
			Path:  p,
			Merge: func(s string) (string, error) { return s, nil },
			Strip: func(_, existing string) (string, bool) { return existing, false },
		}
		out := dryRunRemove(t, f, host)
		if out.Configured || out.Stripped {
			t.Errorf("outcome = %+v", out)
		}
	})

	t.Run("block only ours is deleted", func(t *testing.T) {
		p := filepath.Join(dir, "only.rc")
		writeFile(t, p, Block(pkgMarkers, "export GOPROXY=x")+"\n")
		out := dryRunRemove(t, File{Path: p}, host)
		if !out.Configured || !out.Deleted || out.Stripped {
			t.Errorf("outcome = %+v", out)
		}
	})

	t.Run("block among user content is stripped", func(t *testing.T) {
		p := filepath.Join(dir, "mixed.rc")
		writeFile(t, p, "export PATH=/usr/bin\n"+Block(pkgMarkers, "export GOPROXY=x")+"\n")
		writeFile(t, p+BackupSuffix, "never restored for a block")
		out := dryRunRemove(t, File{Path: p}, host)
		if !out.Configured || !out.Stripped || out.Deleted || out.Restored {
			t.Errorf("outcome = %+v", out)
		}
	})
}

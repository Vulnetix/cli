package imagesrc

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type entry struct {
	name, body, link string
	typ              byte
}

func layer(t *testing.T, entries ...entry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typ, Linkname: e.link}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func image(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestFlattenAppliesWhiteouts(t *testing.T) {
	img := image(t,
		layer(t,
			entry{name: "etc/", typ: tar.TypeDir},
			entry{name: "etc/os-release", body: "ID=alpine\nVERSION_ID=3.19.1\n"},
			entry{name: "lib/apk/db/installed", body: "P:busybox\nV:1.36.1-r15\n\n"},
			entry{name: "tmp/cache/a", body: "a"},
			entry{name: "tmp/cache/b", body: "b"},
			entry{name: "usr/bin/secret", body: "x"},
		),
		layer(t,
			entry{name: "usr/bin/.wh.secret"},
			entry{name: "tmp/cache/.wh..wh..opq"},
			entry{name: "tmp/cache/c", body: "c"},
			entry{name: "bin/sh", typ: tar.TypeSymlink, link: "/bin/busybox"},
		),
		layer(t, entry{name: "lib/apk/db/installed", body: "P:busybox\nV:1.36.1-r15\n\nP:curl\nV:8.5.0-r0\n\n"}),
	)
	dir := t.TempDir()
	var touched []int
	err := Flatten(img, dir, FlattenOptions{AfterLayer: func(i int, db bool) error {
		if db {
			touched = append(touched, i)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "usr/bin/secret")); !os.IsNotExist(err) {
		t.Error("a whiteout removes the lower layer's file")
	}
	if _, err := os.Stat(filepath.Join(dir, "tmp/cache/a")); !os.IsNotExist(err) {
		t.Error("an opaque whiteout empties its directory")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "tmp/cache/c")); string(b) != "c" {
		t.Error("files the opaque layer adds remain")
	}
	if l, err := os.Readlink(filepath.Join(dir, "bin/sh")); err != nil || l != "/bin/busybox" {
		t.Errorf("symlink kept as written: %q %v", l, err)
	}
	if len(touched) != 2 || touched[0] != 0 || touched[1] != 2 {
		t.Errorf("layers that wrote the package database: %v", touched)
	}
}

func TestFlattenRefusesEscapes(t *testing.T) {
	for name, l := range map[string]v1.Layer{
		"dot-dot path":  layer(t, entry{name: "../../etc/passwd", body: "x"}),
		"hard link out": layer(t, entry{name: "x", typ: tar.TypeLink, link: "../../etc/passwd"}),
	} {
		if err := Flatten(image(t, l), t.TempDir(), FlattenOptions{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A symlinked directory pointing out of the root cannot be written through.
	dir := t.TempDir()
	outside := t.TempDir()
	img := image(t,
		layer(t, entry{name: "evil", typ: tar.TypeSymlink, link: outside}),
		layer(t, entry{name: "evil/planted", body: "x"}),
	)
	if err := Flatten(img, dir, FlattenOptions{}); err == nil {
		t.Error("write through a symlink out of the root accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "planted")); err == nil {
		t.Error("a file was planted outside the root")
	}
}

func TestFlattenSizeCap(t *testing.T) {
	img := image(t, layer(t, entry{name: "big", body: string(make([]byte, 1024))}))
	if err := Flatten(img, t.TempDir(), FlattenOptions{MaxBytes: 100}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

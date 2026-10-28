package imagesrc

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// DefaultMaxBytes caps an unpacked image. Images past it are usually build
// toolchains, and reading them should be a deliberate choice (--max-size).
const DefaultMaxBytes int64 = 8 << 30

// ErrTooLarge stops an unpack that would exceed the cap.
var ErrTooLarge = errors.New("image is larger than the unpack limit")

// FlattenOptions control an unpack.
type FlattenOptions struct {
	MaxBytes int64
	// AfterLayer is called once a layer is applied, with its index and whether
	// it wrote a package database; a caller reads the databases then to learn
	// which layer installed each package.
	AfterLayer func(index int, touchedPackageDB bool) error
}

// packageDBPaths are the package databases sysinv reads.
var packageDBPaths = []string{
	"var/lib/dpkg/status", "var/lib/dpkg/status.d/", "lib/apk/db/installed",
	"var/lib/rpm/", "usr/lib/sysimage/rpm/", "var/lib/pacman/local/",
}

// Flatten applies the image's layers in order into dir, as a container runtime
// would: a whiteout (.wh.<name>) deletes what lower layers put there, an opaque
// whiteout (.wh..wh..opq) empties its directory. Nothing is written outside dir:
// entries whose path climbs out are refused, and links are recreated, never
// followed. Device nodes are skipped.
func Flatten(img v1.Image, dir string, opts FlattenOptions) error {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("list layers: %w", err)
	}
	var total int64
	for i, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			return fmt.Errorf("open layer %d: %w", i, err)
		}
		touched, n, err := applyLayer(rc, dir, opts.MaxBytes-total)
		rc.Close()
		total += n
		if err != nil {
			return fmt.Errorf("layer %d: %w", i, err)
		}
		if opts.AfterLayer != nil {
			if err := opts.AfterLayer(i, touched); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyLayer extracts one layer tar into dir and returns whether it wrote a
// package database and how many bytes it wrote.
func applyLayer(r io.Reader, dir string, budget int64) (bool, int64, error) {
	tr := tar.NewReader(r)
	touched := false
	var written int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return touched, written, nil
		}
		if err != nil {
			return touched, written, err
		}
		rel := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		rel = strings.TrimPrefix(rel, "/")
		if rel == "." || rel == "" {
			continue
		}
		if rel == ".." || strings.HasPrefix(rel, "../") {
			return touched, written, fmt.Errorf("entry %q climbs out of the image root", hdr.Name)
		}
		for _, p := range packageDBPaths {
			if rel == strings.TrimSuffix(p, "/") || strings.HasPrefix(rel, p) {
				touched = true
			}
		}
		base := path.Base(rel)
		parent := path.Dir(rel)
		target := filepath.Join(dir, filepath.FromSlash(rel))

		if base == ".wh..wh..opq" {
			if err := emptyDir(filepath.Join(dir, filepath.FromSlash(parent))); err != nil {
				return touched, written, err
			}
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			victim := filepath.Join(dir, filepath.FromSlash(path.Join(parent, strings.TrimPrefix(base, ".wh."))))
			if err := os.RemoveAll(victim); err != nil {
				return touched, written, err
			}
			continue
		}
		if err := ensureParent(dir, target); err != nil {
			return touched, written, err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return touched, written, err
			}
		case tar.TypeReg:
			if written+hdr.Size > budget {
				return touched, written, ErrTooLarge
			}
			_ = os.RemoveAll(target)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return touched, written, err
			}
			n, err := io.Copy(f, io.LimitReader(tr, hdr.Size))
			f.Close()
			written += n
			if err != nil {
				return touched, written, err
			}
		case tar.TypeSymlink:
			// Kept as written, absolute or not: readers join every path under
			// the root and never resolve a link out of it.
			_ = os.RemoveAll(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return touched, written, err
			}
		case tar.TypeLink:
			src := path.Clean(strings.TrimPrefix(strings.TrimPrefix(hdr.Linkname, "./"), "/"))
			if src == ".." || strings.HasPrefix(src, "../") {
				return touched, written, fmt.Errorf("hard link %q points out of the image root", hdr.Linkname)
			}
			_ = os.RemoveAll(target)
			if err := os.Link(filepath.Join(dir, filepath.FromSlash(src)), target); err != nil {
				// A link to a file a whiteout removed: nothing to point at.
				continue
			}
		default:
			// Devices, fifos and the like carry no packages.
		}
	}
}

// ensureParent creates target's directory, refusing a path that resolves out
// of dir through a symlinked component.
func ensureParent(dir, target string) error {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		// A symlinked component makes MkdirAll fail or escape; replace it.
		return err
	}
	real, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	if real != root && !strings.HasPrefix(real, root+string(os.PathSeparator)) {
		return fmt.Errorf("%s resolves outside the image root", target)
	}
	return nil
}

func emptyDir(d string) error {
	entries, err := os.ReadDir(d)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(d, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

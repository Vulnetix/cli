// Package imagesrc reads a container image for `vulnetix scan image`: from a
// registry, from a local docker or podman image store, or from an archive, and
// unpacks its filesystem so the image's own package databases can be read.
//
// Registry credentials come from the user's own docker configuration and
// credential helpers (authn.DefaultKeychain), the same ones `docker pull` uses;
// nothing is stored or sent anywhere else. A local image is exported with the
// engine's own `save` command rather than through a daemon client library,
// which keeps the engine's API out of the CLI.
package imagesrc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Source says where to read the image from.
type Source string

const (
	// SourceAuto tries a local engine for a reference it holds, then the registry.
	SourceAuto     Source = "auto"
	SourceRegistry Source = "registry"
	SourceDocker   Source = "docker"
	SourcePodman   Source = "podman"
	// SourceArchive reads a `docker save` / `podman save` tarball.
	SourceArchive Source = "archive"
)

// Options select the image.
type Options struct {
	Source Source
	// Platform is os/arch[/variant], e.g. linux/amd64; empty means the host's
	// linux architecture.
	Platform string
	// TempDir holds a local engine's export while it is read.
	TempDir string
}

// Meta is what identifies the image that was read.
type Meta struct {
	Ref        string
	Registry   string
	Repository string
	Tag        string
	// Digest is the platform manifest digest.
	Digest string
	// ManifestListDigest is the index the platform manifest was reached through.
	ManifestListDigest string
	Platform           string
	ReadFrom           Source
}

// Image is an opened image.
type Image struct {
	Image  v1.Image
	Meta   Meta
	Config *v1.ConfigFile
	// cleanup removes a temporary export.
	cleanup func()
}

// Close releases what Open made on disk.
func (i *Image) Close() {
	if i != nil && i.cleanup != nil {
		i.cleanup()
	}
}

// Open reads the image ref names.
func Open(ctx context.Context, ref string, opts Options) (*Image, error) {
	if opts.Source == "" {
		opts.Source = SourceAuto
	}
	plat, err := parsePlatform(opts.Platform)
	if err != nil {
		return nil, err
	}
	switch opts.Source {
	case SourceArchive:
		return openArchive(ref, ref, plat)
	case SourceDocker, SourcePodman:
		return openEngine(ctx, string(opts.Source), ref, plat, opts.TempDir)
	case SourceRegistry:
		return openRegistry(ctx, ref, plat)
	case SourceAuto:
		if st, err := os.Stat(ref); err == nil && !st.IsDir() {
			return openArchive(ref, ref, plat)
		}
		for _, engine := range []string{"docker", "podman"} {
			if engineHas(ctx, engine, ref) {
				return openEngine(ctx, engine, ref, plat, opts.TempDir)
			}
		}
		return openRegistry(ctx, ref, plat)
	default:
		return nil, fmt.Errorf("unknown image source %q (auto, registry, docker, podman, archive)", opts.Source)
	}
}

func parsePlatform(s string) (*v1.Platform, error) {
	if s == "" {
		return &v1.Platform{OS: "linux", Architecture: hostArch()}, nil
	}
	p, err := v1.ParsePlatform(s)
	if err != nil {
		return nil, fmt.Errorf("platform %q: %w", s, err)
	}
	return p, nil
}

func openRegistry(ctx context.Context, ref string, plat *v1.Platform) (*Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("image reference %q: %w", ref, err)
	}
	desc, err := remote.Get(r, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithPlatform(*plat))
	if err != nil {
		return nil, explainRegistryError(ref, err)
	}
	meta := metaFor(ref, r)
	meta.ReadFrom = SourceRegistry
	var img v1.Image
	if desc.MediaType.IsIndex() {
		meta.ManifestListDigest = desc.Digest.String()
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, err
		}
		img, err = pickPlatform(idx, plat)
		if err != nil {
			return nil, err
		}
	} else {
		if img, err = desc.Image(); err != nil {
			return nil, err
		}
	}
	return finish(img, meta, nil)
}

func pickPlatform(idx v1.ImageIndex, plat *v1.Platform) (v1.Image, error) {
	man, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	for _, m := range man.Manifests {
		if m.Platform != nil && m.Platform.Satisfies(*plat) {
			return idx.Image(m.Digest)
		}
	}
	return nil, fmt.Errorf("the image has no %s build", plat.String())
}

func openArchive(path, ref string, plat *v1.Platform) (*Image, error) {
	img, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return nil, fmt.Errorf("read image archive %s: %w", path, err)
	}
	meta := Meta{Ref: ref, ReadFrom: SourceArchive}
	if r, err := name.ParseReference(ref); err == nil && !strings.HasSuffix(ref, ".tar") {
		meta = metaFor(ref, r)
		meta.ReadFrom = SourceArchive
	}
	_ = plat
	return finish(img, meta, nil)
}

func openEngine(ctx context.Context, engine, ref string, plat *v1.Platform, tmp string) (*Image, error) {
	dir, err := os.MkdirTemp(tmp, "vulnetix-image-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	out := filepath.Join(dir, "image.tar")
	cmd := exec.CommandContext(ctx, engine, "save", "-o", out, ref)
	if msg, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return nil, fmt.Errorf("%s save %s: %v: %s", engine, ref, err, strings.TrimSpace(string(msg)))
	}
	img, err := tarball.ImageFromPath(out, nil)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("read %s export of %s: %w", engine, ref, err)
	}
	meta := Meta{Ref: ref}
	if r, err := name.ParseReference(ref); err == nil {
		meta = metaFor(ref, r)
	}
	meta.ReadFrom = Source(engine)
	_ = plat
	return finish(img, meta, cleanup)
}

func finish(img v1.Image, meta Meta, cleanup func()) (*Image, error) {
	d, err := img.Digest()
	if err != nil {
		return nil, err
	}
	meta.Digest = d.String()
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read image config: %w", err)
	}
	if cfg.OS != "" {
		meta.Platform = cfg.OS + "/" + cfg.Architecture
		if cfg.Variant != "" {
			meta.Platform += "/" + cfg.Variant
		}
	}
	return &Image{Image: img, Meta: meta, Config: cfg, cleanup: cleanup}, nil
}

func metaFor(ref string, r name.Reference) Meta {
	m := Meta{Ref: ref, Registry: r.Context().RegistryStr(), Repository: r.Context().RepositoryStr()}
	switch t := r.(type) {
	case name.Tag:
		m.Tag = t.TagStr()
	case name.Digest:
		m.ManifestListDigest = t.DigestStr()
	}
	return m
}

// engineHas reports whether a local engine holds ref, without pulling it.
func engineHas(ctx context.Context, engine, ref string) bool {
	if _, err := exec.LookPath(engine); err != nil {
		return false
	}
	return exec.CommandContext(ctx, engine, "image", "inspect", ref).Run() == nil
}

func explainRegistryError(ref string, err error) error {
	if errors.Is(err, remote.ErrSchema1) {
		return fmt.Errorf("%s uses the retired Docker schema 1 manifest format: %w", ref, err)
	}
	s := err.Error()
	if strings.Contains(s, "UNAUTHORIZED") || strings.Contains(s, "DENIED") || strings.Contains(s, "401") {
		return fmt.Errorf("the registry refused access to %s: log in with `docker login %s` (your own credentials are used, never sent to Vulnetix): %w",
			ref, registryOf(ref), err)
	}
	return fmt.Errorf("fetch %s: %w", ref, err)
}

func registryOf(ref string) string {
	if r, err := name.ParseReference(ref); err == nil {
		return r.Context().RegistryStr()
	}
	return ref
}

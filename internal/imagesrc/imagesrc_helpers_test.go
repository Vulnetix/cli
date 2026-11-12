package imagesrc

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestMetaFor(t *testing.T) {
	tag, err := name.ParseReference("ghcr.io/acme/app:1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	m := metaFor("ghcr.io/acme/app:1.2.3", tag)
	if m.Ref != "ghcr.io/acme/app:1.2.3" || m.Registry != "ghcr.io" || m.Repository != "acme/app" || m.Tag != "1.2.3" || m.ManifestListDigest != "" {
		t.Errorf("tag ref meta = %+v", m)
	}

	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	dig, err := name.ParseReference("alpine@" + digest)
	if err != nil {
		t.Fatal(err)
	}
	m = metaFor("alpine@"+digest, dig)
	if m.Registry != "index.docker.io" || m.Repository != "library/alpine" || m.ManifestListDigest != digest || m.Tag != "" {
		t.Errorf("digest ref meta = %+v", m)
	}
}

func TestParsePlatform(t *testing.T) {
	p, err := parsePlatform("")
	if err != nil || p.OS != "linux" || p.Architecture != hostArch() {
		t.Errorf("empty platform = %+v, %v; want linux/%s", p, err, hostArch())
	}

	p, err = parsePlatform("linux/arm64")
	if err != nil || p.OS != "linux" || p.Architecture != "arm64" {
		t.Errorf("linux/arm64 = %+v, %v", p, err)
	}

	p, err = parsePlatform("linux/arm/v7")
	if err != nil || p.Variant != "v7" {
		t.Errorf("linux/arm/v7 = %+v, %v", p, err)
	}

	if _, err := parsePlatform("linux/arm/v7/extra"); err == nil || !strings.Contains(err.Error(), `platform "linux/arm/v7/extra"`) {
		t.Errorf("a malformed platform must fail naming it, got %v", err)
	}
}

func TestExplainRegistryError(t *testing.T) {
	const ref = "ghcr.io/acme/app:1"
	for _, msg := range []string{"UNAUTHORIZED: authentication required", "DENIED: requested access to the resource is denied", "unexpected status code 401"} {
		raw := errors.New(msg)
		err := explainRegistryError(ref, raw)
		if !strings.Contains(err.Error(), "docker login ghcr.io") || !errors.Is(err, raw) {
			t.Errorf("%q: got %v", msg, err)
		}
	}

	schema1 := fmt.Errorf("wrapped: %w", remote.ErrSchema1)
	if err := explainRegistryError(ref, schema1); !strings.Contains(err.Error(), "retired Docker schema 1") || !errors.Is(err, remote.ErrSchema1) {
		t.Errorf("schema 1: got %v", err)
	}

	plain := errors.New("connection reset")
	if err := explainRegistryError(ref, plain); err.Error() != "fetch ghcr.io/acme/app:1: connection reset" {
		t.Errorf("plain error: got %v", err)
	}
}

func TestRegistryOf(t *testing.T) {
	for ref, want := range map[string]string{
		"ghcr.io/acme/app:1":      "ghcr.io",
		"alpine":                  "index.docker.io",
		"localhost:5000/x:latest": "localhost:5000",
		"Not A Valid Ref!!":       "Not A Valid Ref!!",
	} {
		if got := registryOf(ref); got != want {
			t.Errorf("registryOf(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestImageCloseIsSafe(t *testing.T) {
	var nilImage *Image
	nilImage.Close()
	(&Image{}).Close()

	called := 0
	(&Image{cleanup: func() { called++ }}).Close()
	if called != 1 {
		t.Errorf("cleanup ran %d times, want 1", called)
	}
}

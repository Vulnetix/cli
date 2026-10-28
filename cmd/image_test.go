package cmd

import (
	"os"
	"path/filepath"
	"testing"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"

	"github.com/vulnetix/cli/v3/internal/imagesrc"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

func TestRepoFromSourceLabel(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/acme/api":          "acme/api",
		"https://github.com/acme/api.git":      "acme/api",
		"git@github.com:acme/api.git":          "acme/api",
		"https://gitlab.com/acme/team/service": "acme/team",
		"https://example.com":                  "",
		"":                                     "",
	} {
		if got := repoFromSourceLabel(in); got != want {
			t.Errorf("repoFromSourceLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadImageTraits(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"etc/os-release": "ID=alpine\nVERSION_ID=3.19.1\n",
		"sbin/apk":       "",
	} {
		p := filepath.Join(root, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(body), 0o644)
	}
	_ = os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	_ = os.Symlink("/bin/busybox", filepath.Join(root, "bin/sh"))

	cfg := &v1.ConfigFile{Config: v1.Config{User: "node", Env: []string{"PATH=/usr/bin", "NODE_VERSION=20.11.1"}}}
	img := &imagesrc.Image{Config: cfg}
	tr := readImageTraits(root, img, []cyclonedx.SBOMPackage{{Name: "musl"}, {Name: "busybox"}})
	if tr.PurlDistro != "alpine-3.19" || tr.Libc != "musl" || !tr.HasShell || tr.PkgManager != "apk" {
		t.Errorf("distro, libc, shell, package manager: %+v", tr)
	}
	if !tr.NonRoot || tr.DefaultUser != "node" || tr.RuntimeName != "node" || tr.RuntimeVersion != "20.11.1" {
		t.Errorf("user and runtime: %+v", tr)
	}
	root2 := t.TempDir()
	tr = readImageTraits(root2, &imagesrc.Image{Config: &v1.ConfigFile{}}, nil)
	if tr.NonRoot || tr.DefaultUser != "root" || tr.HasShell {
		t.Errorf("an empty config runs as root with no shell found: %+v", tr)
	}
}

func TestBuildImageRequestAttributesLayers(t *testing.T) {
	l0, _ := random.Layer(64, "application/vnd.oci.image.layer.v1.tar")
	l1, _ := random.Layer(64, "application/vnd.oci.image.layer.v1.tar")
	base, err := mutate.AppendLayers(empty.Image, l0, l1)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := base.ConfigFile()
	cfg.Config.Labels = map[string]string{"org.opencontainers.image.source": "https://github.com/acme/api"}
	img := &imagesrc.Image{Image: base, Config: cfg, Meta: imagesrc.Meta{Ref: "acme/api:1", Digest: "sha256:x", Repository: "acme/api", Tag: "1"}}

	pkgs := []cyclonedx.SBOMPackage{
		{Name: "busybox", Version: "1.36.1-r15", Purl: "pkg:apk/alpine/busybox@1.36.1-r15?distro=alpine-3.19"},
		{Name: "curl", Version: "8.5.0-r0", Purl: "pkg:apk/alpine/curl@8.5.0-r0?distro=alpine-3.19"},
		{Name: "express", Version: "4.19.2", Purl: "pkg:npm/express@4.19.2"},
		{Name: "", Purl: "pkg:generic/nameless"},
	}
	first := map[string]int{pkgs[0].Purl: 0, pkgs[1].Purl: 1}
	req := buildImageRequest(img, imageTraits{PurlDistro: "alpine-3.19"}, pkgs, first)

	if len(req.DiffIDs) != 2 || req.Source == nil || req.Source.RepoFullName != "acme/api" {
		t.Fatalf("diff ids and source: %+v", req)
	}
	byName := map[string]int{}
	for i, p := range req.Packages {
		byName[p.Name] = i
	}
	if len(req.Packages) != 3 {
		t.Fatalf("a package without a name is dropped: %+v", req.Packages)
	}
	bb, cu, ex := req.Packages[byName["busybox"]], req.Packages[byName["curl"]], req.Packages[byName["express"]]
	d1, _ := l1.Digest()
	if bb.LayerIndex == nil || *bb.LayerIndex != 0 || cu.LayerIndex == nil || *cu.LayerIndex != 1 || cu.LayerDigest != d1.String() {
		t.Fatalf("OS packages carry the layer that installed them: %+v %+v", bb, cu)
	}
	if ex.LayerIndex != nil {
		t.Fatalf("language packages have no recorded layer: %+v", ex)
	}
}

func TestCollectContainerSources(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(body), 0o644)
	}
	write("Dockerfile", "FROM node:20-alpine\nRUN apk add curl\n")
	write("services/api/Containerfile.prod", "FROM python:3.12-slim AS base\nFROM base\n")
	write("node_modules/pkg/Dockerfile", "FROM ignored:1\n")
	write("docs/README.md", "FROM not-a-dockerfile\n")
	files := collectContainerSources(root)
	if len(files) != 2 {
		t.Fatalf("files: %+v", files)
	}
	byPath := map[string]vdb.CliContainerSourceFile{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	if f := byPath["Dockerfile"]; len(f.Stages) != 1 || f.Stages[0].ResolvedRef != "node:20-alpine" || len(f.Stages[0].Installs) != 1 {
		t.Errorf("Dockerfile: %+v", f)
	}
	if f := byPath["services/api/Containerfile.prod"]; len(f.Stages) != 2 || f.Stages[1].FromStage != "base" || !f.Stages[1].IsFinal {
		t.Errorf("Containerfile.prod: %+v", f)
	}
}

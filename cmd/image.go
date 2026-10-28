package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/imagesrc"
	"github.com/vulnetix/cli/v3/internal/sysinv"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// imageCmd inventories one container image and records it for container
// curation: its identity and layer chain (which recognise the base it was
// built FROM), the traits a base image swap keeps or changes, and its packages
// with the layer that installed each.
var imageCmd = &cobra.Command{
	Use:   "image <reference | archive.tar>",
	Short: "Inventory a container image for container curation",
	Long: `Read a container image, inventory its packages layer by layer and record it
so the Container curation page can compare its base image with the equivalent
images on other registries.

The image is read from a local docker or podman image store when one holds it,
otherwise from its registry with your own docker credentials (docker login and
credential helpers; nothing is sent to Vulnetix but the inventory), or from an
archive made by docker save or podman save.

Examples:
  vulnetix image node:20.11.1-alpine3.19
  vulnetix image ghcr.io/acme/api:2026.10.27 --platform linux/arm64
  vulnetix image ./api.tar --output api.cdx.json --no-upload`,
	Args: cobra.ExactArgs(1),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		noUpload, _ := cmd.Flags().GetBool("no-upload")
		return resolveVDBCredentials(noUpload)
	},
	RunE: runImage,
}

func init() {
	imageCmd.Flags().String("source", "auto", "Where to read the image: auto, registry, docker, podman or archive")
	imageCmd.Flags().String("platform", "", "Platform to read from a multi-platform image, e.g. linux/arm64 (default: this machine's)")
	imageCmd.Flags().StringP("output", "o", "", "Also write the image's CycloneDX SBOM to this file")
	imageCmd.Flags().Int64("max-size-mb", imagesrc.DefaultMaxBytes>>20, "Refuse to unpack more than this many MiB")
	imageCmd.Flags().Bool("no-upload", false, "Inventory locally only; record nothing")
	imageCmd.Flags().Bool("no-language-packages", false, "Skip npm, pip, gem, Go and other language packages installed in the image")
	rootCmd.AddCommand(imageCmd)
}

func runImage(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ref := args[0]
	source, _ := cmd.Flags().GetString("source")
	platform, _ := cmd.Flags().GetString("platform")
	outFile, _ := cmd.Flags().GetString("output")
	maxMB, _ := cmd.Flags().GetInt64("max-size-mb")
	noUpload, _ := cmd.Flags().GetBool("no-upload")
	noLang, _ := cmd.Flags().GetBool("no-language-packages")

	img, err := imagesrc.Open(ctx, ref, imagesrc.Options{Source: imagesrc.Source(source), Platform: platform})
	if err != nil {
		return err
	}
	defer img.Close()
	fmt.Fprintf(os.Stderr, "Reading %s (%s, %s) from %s\n", ref, img.Meta.Digest, img.Meta.Platform, img.Meta.ReadFrom)

	root, err := os.MkdirTemp("", "vulnetix-image-rootfs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)

	// A package's layer is the first layer whose package database lists it:
	// reading the databases after every layer that wrote one is what tells the
	// base image's packages from the ones the image's own RUN lines added.
	firstLayer := map[string]int{}
	err = imagesrc.Flatten(img.Image, root, imagesrc.FlattenOptions{
		MaxBytes: maxMB << 20,
		AfterLayer: func(i int, touched bool) error {
			if !touched {
				return nil
			}
			res := sysinv.Collect(root)
			for _, p := range res.Packages {
				if _, ok := firstLayer[p.Purl(res.Distro)]; !ok {
					firstLayer[p.Purl(res.Distro)] = i
				}
			}
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("unpack %s: %w", ref, err)
	}

	label := imageLabel(img.Meta)
	pkgs, warns := collectSystemDBPackages(root, root, label, false)
	if !noLang {
		pkgs = append(pkgs, collectInstalledPackages(cdxRunOptions{RootPath: root, IncludeSystem: true, SystemRoot: root, NoSignatures: true})...)
	}
	pkgs = dedupeCDXPackages(pkgs)
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "warning: "+w)
	}

	traits := readImageTraits(root, img, pkgs)
	req := buildImageRequest(img, traits, pkgs, firstLayer)

	if outFile != "" {
		if err := writeImageSBOM(outFile, img, pkgs); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "SBOM written to %s\n", outFile)
	}

	fmt.Fprintf(os.Stderr, "%s: %d packages, %s, libc %s, package manager %s\n",
		label, len(req.Packages), orNone(traits.PurlDistro), orNone(traits.Libc), orNone(traits.PkgManager))

	if noUpload {
		return nil
	}
	if vdbCreds == nil {
		fmt.Fprintln(os.Stderr, "No credentials: nothing recorded. Run `vulnetix auth login`, or pass --no-upload.")
		return nil
	}
	client := vdb.NewClientFromCredentials(vdbCreds)
	client.NoCache = true
	cwd, _ := os.Getwd()
	resp, err := client.CliImage(vdb.SnapshotEnv(cwd, version, commit, buildDate), req)
	if err != nil {
		return fmt.Errorf("record image: %w", err)
	}
	d := resp.Data
	switch {
	case !d.Persisted:
		fmt.Fprintln(os.Stderr, "Inventory checked; your plan does not record images.")
	case d.BaseRef != "":
		fmt.Fprintf(os.Stderr, "Recorded. Built FROM %s (matched by %s). See Container curation in Resolve.\n", d.BaseRef, d.BaseResolution)
	default:
		fmt.Fprintln(os.Stderr, "Recorded. Its base image is not one Vulnetix has crawled yet.")
	}
	if d.WorkloadsLinked > 0 {
		fmt.Fprintf(os.Stderr, "Running in %d place(s) found by your cloud scans.\n", d.WorkloadsLinked)
	}
	return nil
}

func imageLabel(m imagesrc.Meta) string {
	if m.Repository != "" {
		if m.Tag != "" {
			return m.Repository + ":" + m.Tag
		}
		return m.Repository
	}
	return filepath.Base(m.Ref)
}

func orNone(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// imageTraits is what a base image swap keeps or changes.
type imageTraits struct {
	OS, OSRelease, PurlDistro, Libc string
	HasShell, NonRoot               bool
	DefaultUser, PkgManager         string
	RuntimeName, RuntimeVersion     string
}

var pkgManagerBinaries = []struct{ path, name string }{
	{"sbin/apk", "apk"}, {"usr/bin/apt-get", "apt"}, {"usr/bin/microdnf", "microdnf"},
	{"usr/bin/dnf", "dnf"}, {"usr/bin/yum", "yum"}, {"usr/bin/pacman", "pacman"}, {"usr/bin/zypper", "zypper"},
}

var runtimeEnv = []struct{ env, name string }{
	{"NODE_VERSION", "node"}, {"PYTHON_VERSION", "python"}, {"JAVA_VERSION", "java"},
	{"GOLANG_VERSION", "go"}, {"RUBY_VERSION", "ruby"}, {"PHP_VERSION", "php"},
	{"DOTNET_VERSION", "dotnet"}, {"ASPNET_VERSION", "dotnet"},
}

func readImageTraits(root string, img *imagesrc.Image, pkgs []cyclonedx.SBOMPackage) imageTraits {
	d := sysinv.ReadOSRelease(root)
	t := imageTraits{OS: d.ID, OSRelease: d.VersionID, PurlDistro: d.Release()}
	if t.PurlDistro == "" {
		t.PurlDistro = d.Namespace()
	}
	for _, p := range pkgs {
		switch strings.ToLower(p.Name) {
		case "musl":
			t.Libc = "musl"
		case "libc6", "glibc", "glibc-minimal-langpack", "glibc-common":
			if t.Libc == "" {
				t.Libc = "glibc"
			}
		}
	}
	for _, sh := range []string{"bin/sh", "bin/bash", "bin/ash", "usr/bin/sh"} {
		if _, err := os.Lstat(filepath.Join(root, sh)); err == nil {
			t.HasShell = true
			break
		}
	}
	for _, m := range pkgManagerBinaries {
		if _, err := os.Lstat(filepath.Join(root, m.path)); err == nil {
			t.PkgManager = m.name
			break
		}
	}
	if img.Config != nil {
		user := strings.TrimSpace(img.Config.Config.User)
		t.DefaultUser = user
		if user == "" {
			t.DefaultUser = "root"
		}
		t.NonRoot = user != "" && user != "root" && user != "0" && !strings.HasPrefix(user, "0:") && !strings.HasPrefix(user, "root:")
		for _, kv := range img.Config.Config.Env {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			for _, r := range runtimeEnv {
				if k == r.env && t.RuntimeName == "" {
					t.RuntimeName, t.RuntimeVersion = r.name, strings.TrimPrefix(v, "v")
				}
			}
		}
	}
	return t
}

func buildImageRequest(img *imagesrc.Image, t imageTraits, pkgs []cyclonedx.SBOMPackage, firstLayer map[string]int) vdb.CliImageRequest {
	req := vdb.CliImageRequest{
		Ref: img.Meta.Ref, Registry: img.Meta.Registry, Repository: img.Meta.Repository, Tag: img.Meta.Tag,
		Digest: img.Meta.Digest, ManifestListDigest: img.Meta.ManifestListDigest, Platform: img.Meta.Platform,
		OS: t.OS, OSRelease: t.OSRelease, PurlDistro: t.PurlDistro, Libc: t.Libc,
		HasShell: &t.HasShell, NonRoot: &t.NonRoot, DefaultUser: t.DefaultUser, PkgManager: t.PkgManager,
		RuntimeName: t.RuntimeName, RuntimeVersion: t.RuntimeVersion,
	}
	if img.Config != nil {
		for _, d := range img.Config.RootFS.DiffIDs {
			req.DiffIDs = append(req.DiffIDs, d.String())
		}
		req.Labels = img.Config.Config.Labels
		if src := img.Config.Config.Labels["org.opencontainers.image.source"]; src != "" {
			if repo := repoFromSourceLabel(src); repo != "" {
				req.Source = &vdb.CliImageSourceRef{RepoFullName: repo}
			}
		}
	}
	if layers, err := img.Image.Layers(); err == nil {
		digests := make([]string, len(layers))
		for i, l := range layers {
			if d, err := l.Digest(); err == nil {
				digests[i] = d.String()
			}
		}
		for _, p := range pkgs {
			if p.Purl == "" || p.Name == "" {
				continue
			}
			ip := vdb.CliImagePackage{Purl: p.Purl, Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem}
			if i, ok := firstLayer[p.Purl]; ok {
				idx := i
				ip.LayerIndex = &idx
				if i < len(digests) {
					ip.LayerDigest = digests[i]
				}
			}
			req.Packages = append(req.Packages, ip)
		}
	}
	sort.Slice(req.Packages, func(i, j int) bool { return req.Packages[i].Purl < req.Packages[j].Purl })
	return req
}

// repoFromSourceLabel reads owner/repo from org.opencontainers.image.source
// (https://github.com/acme/api, git@github.com:acme/api.git).
func repoFromSourceLabel(src string) string {
	s := strings.TrimSuffix(strings.TrimSpace(src), ".git")
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else if i := strings.Index(s, "@"); i >= 0 {
		s = strings.Replace(s[i+1:], ":", "/", 1)
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[1] + "/" + parts[2]
}

func writeImageSBOM(path string, img *imagesrc.Image, pkgs []cyclonedx.SBOMPackage) error {
	authorship := cdx.Authoring(cyclonedx.ToolCDX, cdx.ResolveManufacturer(cdx.ManufacturerSources{}),
		cdx.DerivePhases(cdx.LifecycleSources{ContainerImage: true, InstalledTree: true})...)
	inv := cdxInventory{Packages: pkgs}
	data, err := cyclonedx.BuildSBOM(cyclonedx.SBOMInventory{Packages: pkgs, Dependencies: buildCDXDependencies(inv)},
		cyclonedx.SBOMOptions{SpecVersion: "1.7", Authorship: &authorship})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

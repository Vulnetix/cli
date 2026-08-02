package cmd

// `tea release` publishes everything about a release in one command.
//
// Done by hand this is five calls in a fixed order — product, release,
// collection, artifact, content — and a pipeline that gets the order wrong
// publishes a collection with no artifacts in it, which reads to a consumer as
// a release that shipped no evidence. Getting that right once, here, is the
// point of the command.
//
// It is built to be the last step of a GitHub Actions release job, so every
// input it can read from the environment, it does: the repository names the
// product, the tag names the version, and the release date is the tag's. What
// remains is which files to publish.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/tea"
)

func newTeaReleaseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release [files...]",
		Short: "Publish a complete release to the transparency log in one command",
		Long: `Publish a product, a release, its collection and every artifact, in order.

Intended as the final step of a release pipeline:

    - name: Publish transparency data
      run: vulnetix tea release dist/*.cdx.json dist/*.spdx.json vex.json

Inside GitHub Actions the product name, version and release date are read from
the environment (GITHUB_REPOSITORY, GITHUB_REF_NAME) unless given explicitly.
Each file's name decides its media type and TEA artifact type, and its SHA-256
is computed locally and verified by the server before anything is stored.

Every step is idempotent on the identity it derives, so re-running a failed job
republishes rather than duplicating — which matters, because the alternative is
a duplicate that a consumer finds rather than you.

Nothing is readable by anyone else until you say so. Pass --visibility to set
that as part of the same run; public cannot be undone.`,
		RunE: runTeaRelease,
	}
	cmd.Flags().String("product", "", "product name; defaults to the GitHub repository")
	cmd.Flags().String("version", "", "release version; defaults to the tag")
	cmd.Flags().String("date", "", "release date (RFC3339); defaults to now")
	cmd.Flags().Bool("pre-release", false, "mark the release as a pre-release")
	cmd.Flags().String("reason", "", "collection update reason; INITIAL_RELEASE for a new release, ARTIFACT_ADDED otherwise")
	cmd.Flags().String("visibility", "", "set the product's visibility once published: private, shared or public")
	cmd.Flags().StringSlice("org", nil, "organisation UUID to share with, with --visibility shared")
	cmd.Flags().Bool("dry-run", false, "print what would be published and exit")
	return cmd
}

// teaReleaseInputs is everything the command needs, after defaults.
type teaReleaseInputs struct {
	Product    string
	Version    string
	Date       string
	PreRelease bool
	Files      []string
}

// resolveTeaReleaseInputs fills what was not given from the environment.
//
// GitHub Actions is the intended caller, so its variables are the defaults. A
// tag like `v1.2.3` keeps its `v`: the tag is what the release is called
// upstream, and quietly renaming it would break the link between what TEA
// publishes and what a user sees on the releases page.
func resolveTeaReleaseInputs(cmd *cobra.Command, args []string) (teaReleaseInputs, error) {
	in := teaReleaseInputs{Files: args}

	in.Product, _ = cmd.Flags().GetString("product")
	if in.Product == "" {
		in.Product = strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	}
	if in.Product == "" {
		return in, fmt.Errorf("--product is required outside GitHub Actions (GITHUB_REPOSITORY was not set)")
	}

	in.Version, _ = cmd.Flags().GetString("version")
	if in.Version == "" {
		// GITHUB_REF_NAME is the tag for a tag-triggered run, which is what a
		// release job is. On a branch run it is the branch, which is not a
		// release, so the caller is told rather than having a branch name
		// published as a version.
		if strings.EqualFold(os.Getenv("GITHUB_REF_TYPE"), "tag") {
			in.Version = strings.TrimSpace(os.Getenv("GITHUB_REF_NAME"))
		}
	}
	if in.Version == "" {
		return in, fmt.Errorf("--version is required: no release tag was found in the environment "+
			"(GITHUB_REF_TYPE was %q)", os.Getenv("GITHUB_REF_TYPE"))
	}

	in.Date, _ = cmd.Flags().GetString("date")
	if in.Date == "" {
		in.Date = time.Now().UTC().Format(time.RFC3339)
	}
	in.PreRelease, _ = cmd.Flags().GetBool("pre-release")

	expanded, err := expandTeaReleaseFiles(args)
	if err != nil {
		return in, err
	}
	in.Files = expanded
	return in, nil
}

// expandTeaReleaseFiles resolves globs and drops anything unreadable.
//
// A shell usually expands these, but a workflow `run:` step with quoting, or a
// pattern that matched nothing, does not — and a glob passed through literally
// would otherwise be published as a file named `dist/*.cdx.json`.
func expandTeaReleaseFiles(args []string) ([]string, error) {
	seen := map[string]bool{}
	var files []string

	for _, a := range args {
		matches := []string{a}
		if strings.ContainsAny(a, "*?[") {
			m, err := filepath.Glob(a)
			if err != nil {
				return nil, fmt.Errorf("pattern %q: %w", a, err)
			}
			matches = m
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || info.IsDir() {
				continue
			}
			abs, _ := filepath.Abs(m)
			if seen[abs] {
				continue
			}
			seen[abs] = true
			files = append(files, m)
		}
	}
	sort.Strings(files)
	return files, nil
}

func runTeaRelease(cmd *cobra.Command, args []string) error {
	in, err := resolveTeaReleaseInputs(cmd, args)
	if err != nil {
		return err
	}
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	if len(in.Files) == 0 {
		// Publishing a release with no evidence is legitimate — the release
		// object still exists and is still resolvable — but it is almost never
		// what a pipeline meant, so it is said out loud.
		fmt.Fprintln(os.Stderr, "warning: no artifact files matched; publishing the release with an empty collection")
	}

	fmt.Printf("product   %s\n", in.Product)
	fmt.Printf("version   %s\n", in.Version)
	fmt.Printf("released  %s\n", in.Date)
	for _, f := range in.Files {
		fmt.Printf("artifact  %-40s %s\n", filepath.Base(f), tea.MediaTypeForFile(f))
	}
	if dryRun {
		fmt.Fprintln(os.Stderr, "\ndry run — nothing was published")
		return nil
	}

	ctx, cancel := teaContext(cmd)
	defer cancel()
	c := teaClient(cmd)

	// 1. Product. Idempotent on the name, so a re-run finds the same object
	//    rather than creating a second one.
	product, err := c.CreateProduct(ctx, in.Product,
		[]tea.Identifier{{IDType: "PURL", IDValue: teaReleasePURL(in.Product)}},
		"cli-product-"+in.Product)
	if err != nil {
		return teaFail(err)
	}

	// 2. Release.
	release, err := c.CreateProductRelease(ctx, product.UUID, in.Version, in.Date, in.PreRelease,
		"cli-release-"+product.UUID+"-"+in.Version)
	if err != nil {
		return teaFail(err)
	}

	// 3. Collection. The reason defaults by what is actually happening: a
	//    release whose collection does not exist yet is an initial release,
	//    and anything after that is an addition.
	reason, _ := cmd.Flags().GetString("reason")
	if reason == "" {
		reason = "INITIAL_RELEASE"
		if existing, err := c.LatestCollection(ctx, release.UUID); err == nil && existing.Version > 0 {
			reason = "ARTIFACT_ADDED"
		}
	}
	collection, err := c.PublishCollection(ctx, release.UUID, tea.UpdateReason{
		Type:    reason,
		Comment: fmt.Sprintf("Published by the Vulnetix CLI for %s %s", in.Product, in.Version),
	})
	if err != nil {
		return teaFail(err)
	}

	// 4. Artifacts, each registered then uploaded.
	published := 0
	for _, f := range in.Files {
		name := filepath.Base(f)
		mediaType := tea.MediaTypeForFile(f)

		art, err := c.CreateArtifact(ctx, collection.UUID, name, tea.ArtifactTypeForFile(f),
			[]tea.Format{{MediaType: mediaType}}, "cli-artifact-"+collection.UUID+"-"+name)
		if err != nil {
			return teaFail(fmt.Errorf("register %s: %w", name, err))
		}
		if _, err := c.UploadArtifactFile(ctx, art.UUID, 0, f, mediaType); err != nil {
			return teaFail(fmt.Errorf("upload %s: %w", name, err))
		}
		published++
	}

	// 5. Visibility, if the caller asked for it in the same run.
	visibility, _ := cmd.Flags().GetString("visibility")
	if visibility != "" {
		orgs, _ := cmd.Flags().GetStringSlice("org")
		if visibility == "shared" && len(orgs) == 0 {
			return fmt.Errorf("--visibility shared needs at least one --org")
		}
		grants := make([]tea.ShareGrant, 0, len(orgs))
		for _, o := range orgs {
			grants = append(grants, tea.ShareGrant{OrganizationUUID: strings.TrimSpace(o)})
		}
		if _, err := c.SetAccessPolicy(ctx, product.UUID, tea.AccessPolicy{
			Visibility: visibility,
			SharedWith: grants,
		}); err != nil {
			return teaFail(err)
		}
	}

	if teaJSONFlag(cmd) {
		return teaPrintJSON(map[string]any{
			"product":    product.UUID,
			"release":    release.UUID,
			"collection": collection.Version,
			"artifacts":  published,
			"visibility": visibility,
		})
	}

	fmt.Printf("\npublished %d artifact(s) in collection v%d\n", published, collection.Version)
	fmt.Printf("product   %s\n", product.UUID)
	fmt.Printf("release   %s\n", release.UUID)
	if visibility == "" {
		fmt.Fprintf(os.Stderr,
			"\nNothing is readable by anyone else yet. To publish it:\n"+
				"  vulnetix tea share %s --visibility public\n", product.UUID)
	}
	return nil
}

// teaReleasePURL names a GitHub repository as a Package URL.
//
// Only owner/repo produces one. Anything else gets no purl rather than a
// guessed one: an identifier that names the wrong thing is worse than an
// absent identifier, because a consumer will follow it.
func teaReleasePURL(repository string) string {
	owner, repo, ok := strings.Cut(strings.TrimSpace(repository), "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return ""
	}
	return "pkg:github/" + owner + "/" + repo
}

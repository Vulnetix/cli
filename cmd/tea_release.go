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
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/github"
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
	cmd.Flags().Bool("auto-version", false,
		"outside a tag run, derive the version from `git describe` and mark it a pre-release")
	cmd.Flags().String("date", "", "release date (RFC3339); defaults to now")
	cmd.Flags().Bool("pre-release", false, "mark the release as a pre-release")
	cmd.Flags().String("reason", "", "collection update reason; INITIAL_RELEASE for a new release, ARTIFACT_ADDED otherwise")
	cmd.Flags().String("visibility", "", "set the product's visibility once published: private, shared or public")
	cmd.Flags().StringSlice("org", nil, "organisation UUID to share with, with --visibility shared")
	cmd.Flags().Bool("dry-run", false, "print what would be published and exit")
	cmd.Flags().String("checksums", "",
		"sha256sum manifest whose files become the release's distributions")
	cmd.Flags().Bool("checksums-from-release", false,
		"on a tag run, take --checksums from the GitHub release's checksums asset")
	cmd.Flags().String("base-url", "",
		"URL each file in --checksums is served from; defaults to the GitHub release's download URL")
	cmd.Flags().StringSlice("exclude", nil, "file name in --checksums to skip (repeatable)")
	// StringArray, not StringSlice: a channel spec is itself comma-separated,
	// and pflag's slice parsing would split `name=Homebrew,url=…` into two
	// values, each of which then fails to parse as a whole channel.
	cmd.Flags().StringArray("channel", nil,
		"install channel with no single file to fetch, as `name=…[,url=…][,purl=…]` (repeatable)")
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
	// A branch push is not a release, but it still produced evidence worth
	// publishing. Derive a version for it rather than refusing, and say in the
	// object itself that it is not a release: `--pre-release` is forced here
	// because a caller cannot know in advance which of the two cases it is in.
	if in.Version == "" {
		if auto, _ := cmd.Flags().GetBool("auto-version"); auto {
			v, err := gitDescribeVersion()
			if err != nil {
				return in, fmt.Errorf("--auto-version: %w", err)
			}
			in.Version = v
			in.PreRelease = true
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
	// Already true when --auto-version derived the version, so this ORs rather
	// than assigns: an explicit --pre-release adds to the decision, it does not
	// overwrite it.
	pre, _ := cmd.Flags().GetBool("pre-release")
	in.PreRelease = in.PreRelease || pre

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

	// Resolved before the dry-run exit, so `--dry-run` reports the download
	// links too and a malformed --channel is caught without a release having
	// been half-published to find out.
	distributions, err := teaReleaseDistributions(cmd, in)
	if err != nil {
		return err
	}

	fmt.Printf("product   %s\n", in.Product)
	fmt.Printf("version   %s\n", in.Version)
	fmt.Printf("released  %s\n", in.Date)
	for _, f := range in.Files {
		fmt.Printf("artifact  %-40s %s\n", filepath.Base(f), tea.MediaTypeForFile(f))
	}
	for _, d := range distributions {
		fmt.Printf("download  %-40s %s\n", d.Description, d.URL)
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

	// 2b. The component and its release.
	//
	// A product is what somebody buys; a component is a thing that ships, and
	// the two are separate objects because a release of one is not a release of
	// the other. Publishing both is not optional bookkeeping:
	//
	//   - `productRelease.components` is REQUIRED by the consumption schema, so
	//     a product release with no component release to point at serialises a
	//     field a conformant consumer will reject.
	//   - Only `release.distributions` exists. A product release cannot carry a
	//     download link at all, so without this step there is nowhere to say
	//     where the release is obtained.
	//
	// Same name, same version — derived identically on the server, so this is
	// idempotent alongside everything else here.
	component, err := c.CreateComponent(ctx, in.Product,
		[]tea.Identifier{{IDType: "PURL", IDValue: teaReleasePURL(in.Product)}},
		"cli-component-"+in.Product)
	if err != nil {
		return teaFail(err)
	}
	componentRelease, err := c.CreateComponentRelease(ctx, component.UUID, in.Version, in.Date, in.PreRelease,
		"cli-component-release-"+component.UUID+"-"+in.Version)
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

	// 5. Distributions — where the release is actually obtained.
	//
	// Published after the artifacts because a failure here should not lose the
	// evidence that already uploaded: a release with SBOMs and no download links
	// is incomplete, whereas one with links and no SBOMs is a release that
	// silently claims to have published nothing about itself.
	for _, d := range distributions {
		if _, err := c.CreateDistribution(ctx, componentRelease.UUID, d,
			teaDistributionKey(componentRelease.UUID, d)); err != nil {
			return teaFail(fmt.Errorf("publish distribution %s: %w", distributionLabel(d), err))
		}
	}

	// 6. Visibility, if the caller asked for it in the same run.
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
		// Both roots, not just the product.
		//
		// A release published here spans two lineages: the product holds the
		// evidence, and the component holds the distributions. Policy inherits
		// downwards from each root separately, so setting only the product left
		// every download link private while the SBOM above it was public —
		// publishing the description of a release and withholding the release.
		for _, root := range []string{product.UUID, component.UUID} {
			if _, err := c.SetAccessPolicy(ctx, root, tea.AccessPolicy{
				Visibility: visibility,
				SharedWith: grants,
			}); err != nil {
				return teaFail(err)
			}
		}
	}

	if teaJSONFlag(cmd) {
		return teaPrintJSON(map[string]any{
			"product":          product.UUID,
			"release":          release.UUID,
			"component":        component.UUID,
			"componentRelease": componentRelease.UUID,
			"collection":       collection.Version,
			"artifacts":        published,
			"distributions":    len(distributions),
			"visibility":       visibility,
		})
	}

	fmt.Printf("\npublished %d artifact(s) in collection v%d\n", published, collection.Version)
	if len(distributions) > 0 {
		fmt.Printf("published %d distribution(s)\n", len(distributions))
	}
	fmt.Printf("product           %s\n", product.UUID)
	fmt.Printf("release           %s\n", release.UUID)
	fmt.Printf("component         %s\n", component.UUID)
	fmt.Printf("component release %s\n", componentRelease.UUID)
	if visibility == "" {
		// Both roots, because the evidence and the download links inherit from
		// different ones. Naming only the product here is how a publisher ends
		// up with a public SBOM describing a release nobody can reach.
		fmt.Fprintf(os.Stderr,
			"\nNothing is readable by anyone else yet. To publish it:\n"+
				"  vulnetix tea share %s --visibility public   # evidence\n"+
				"  vulnetix tea share %s --visibility public   # downloads\n",
			product.UUID, component.UUID)
	}
	return nil
}

// teaReleaseDistributions builds the release's download links.
//
// Two sources, because a release is obtained two different ways:
//
//   - The files it publishes, read from the checksums manifest the release
//     already ships. Taking the digests from that file rather than recomputing
//     them means the checksum a consumer reads through TEA is the same string
//     the project published, not a second one that could disagree with it.
//   - The install channels that carry no single file — Homebrew, Scoop, Nix.
//     A user runs `brew install`; there is nothing to fetch and nothing to
//     checksum, so these are named rather than linked.
func teaReleaseDistributions(cmd *cobra.Command, in teaReleaseInputs) ([]tea.Distribution, error) {
	var out []tea.Distribution

	manifest, err := resolveChecksumsManifest(cmd)
	if err != nil {
		return nil, err
	}
	if manifest != "" {
		base, _ := cmd.Flags().GetString("base-url")
		if base == "" {
			// In a GitHub release job the answer is known, and making the
			// caller repeat it is how the two drift apart.
			base = teaGitHubDownloadBase(in.Product, in.Version)
		}
		if base == "" {
			return nil, fmt.Errorf("--checksums needs --base-url outside GitHub Actions: " +
				"a file name is not a download link")
		}
		exclude, _ := cmd.Flags().GetStringSlice("exclude")
		parsed, err := distributionsFromChecksums(manifest, base, exclude)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed...)
	}

	channels, _ := cmd.Flags().GetStringArray("channel")
	for _, spec := range channels {
		d, err := parseChannelSpec(spec)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// parseChannelSpec reads `name=Homebrew tap,url=…,purl=…`.
//
// `name` is required: a channel a user cannot recognise by name is a row in a
// list nobody can act on. Unknown keys are refused rather than ignored, because
// a typo that silently drops a URL publishes a channel with no way to reach it.
func parseChannelSpec(spec string) (tea.Distribution, error) {
	var d tea.Distribution
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return d, fmt.Errorf("--channel %q: expected key=value pairs separated by commas", spec)
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name", "description":
			d.Description = value
		case "url":
			d.URL = value
		case "purl":
			if value != "" {
				d.Identifiers = append(d.Identifiers, tea.Identifier{IDType: "PURL", IDValue: value})
			}
		default:
			return d, fmt.Errorf("--channel %q: unknown key %q (use name, url or purl)", spec, key)
		}
	}
	if d.Description == "" {
		return d, fmt.Errorf("--channel %q: name is required", spec)
	}
	return d, nil
}

// teaGitHubDownloadBase is where a GitHub release serves its assets.
//
// Only derivable inside a GitHub Actions run of the repository being released:
// GITHUB_SERVER_URL names the host, which matters for GitHub Enterprise, and
// guessing github.com there would publish links into the wrong instance.
func teaGitHubDownloadBase(repository, version string) string {
	if repository == "" || version == "" {
		return ""
	}
	if _, _, ok := strings.Cut(repository, "/"); !ok {
		return ""
	}
	server := strings.TrimRight(strings.TrimSpace(os.Getenv("GITHUB_SERVER_URL")), "/")
	if server == "" {
		return ""
	}
	return server + "/" + repository + "/releases/download/" + version
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

// gitDescribeVersion names the current commit relative to the last tag.
//
// `v3.75.0-12-gabc1234` sorts after the release it descends from, says how far
// past it the commit is, and resolves back to that commit. `--always` matters
// more than it looks: most repositories in the fleet have never been tagged, and
// without it they would fail to publish rather than publish a SHA.
func gitDescribeVersion() (string, error) {
	out, err := exec.Command("git", "describe", "--tags", "--always").Output()
	if err != nil {
		return "", fmt.Errorf("git describe: %w", err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", fmt.Errorf("git describe produced no output")
	}
	return v, nil
}

// resolveChecksumsManifest decides which checksums file, if any, to publish
// distributions from.
//
// Three ways it legitimately resolves to nothing, none of which is a failure:
// the flag is off, the run is not a tag run, or the release ships no such
// asset. A release with evidence and no download links is incomplete; a job
// that died trying to find one publishes nothing at all, which is worse.
func resolveChecksumsManifest(cmd *cobra.Command) (string, error) {
	if explicit, _ := cmd.Flags().GetString("checksums"); explicit != "" {
		return explicit, nil
	}
	if fromRelease, _ := cmd.Flags().GetBool("checksums-from-release"); !fromRelease {
		return "", nil
	}
	if !strings.EqualFold(os.Getenv("GITHUB_REF_TYPE"), "tag") {
		return "", nil
	}

	repository := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	tag := strings.TrimSpace(os.Getenv("GITHUB_REF_NAME"))
	if repository == "" || tag == "" {
		return "", nil
	}
	apiURL := strings.TrimSpace(os.Getenv("GITHUB_API_URL"))
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}

	ctx, cancel := teaContext(cmd)
	defer cancel()

	rel, err := github.FetchReleaseByTag(ctx, os.Getenv("GITHUB_TOKEN"), apiURL, repository, tag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read the GitHub release for %s: %v\n", tag, err)
		return "", nil
	}
	asset := rel.AssetMatching("checksums")
	if asset == nil {
		fmt.Fprintf(os.Stderr, "warning: release %s publishes no checksums asset; no distributions will be published\n", tag)
		return "", nil
	}

	dir, err := os.MkdirTemp("", "vulnetix-tea-")
	if err != nil {
		return "", err
	}
	path, err := github.DownloadAsset(ctx, os.Getenv("GITHUB_TOKEN"), *asset, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not download %s: %v\n", asset.Name, err)
		return "", nil
	}
	return path, nil
}

package cmd

// `tea distribution` — where a release is actually obtained.
//
// A collection answers "what evidence exists about this release". Distributions
// answer "how do I install it", and until they are published a consumer that
// resolved a TEI has an SBOM and no download link. The two are separate objects
// in the specification for that reason, and only a COMPONENT release carries
// distributions: `release.distributions` is defined, `productRelease` has no
// such field.
//
// Homebrew and Scoop are distributions in exactly this sense. They deliver the
// same release the GitHub assets do, through a channel a user invokes rather
// than a file they fetch — which is why a distribution may carry a description
// and no URL.

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/tea"
)

func newTeaDistributionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "distribution",
		Aliases: []string{"dist"},
		Short:   "Publish and inspect where a release can be obtained",
		Long: `Manage the download links and install channels of a component release.

    add     declare one download, or a whole checksums file at once
    list    show what a release currently advertises
    remove  withdraw a link

Withdrawing a link stops it being advertised. It does not unpublish the file it
pointed at, and it does not reach anyone who already downloaded it.`,
	}
	cmd.AddCommand(
		newTeaDistributionAddCommand(),
		newTeaDistributionListCommand(),
		newTeaDistributionRemoveCommand(),
	)
	return cmd
}

func newTeaDistributionAddCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <component-release-uuid>",
		Short: "Declare a download or install channel for a release",
		Long: `Add one distribution, or every file in a checksums manifest at once.

One at a time:

    vulnetix tea distribution add $REL \
      --url https://example.com/tool-linux-amd64 \
      --description "Linux x86-64 binary" \
      --sha256 b9f62ff7...

A whole release's assets, from the checksums file the release already
publishes:

    vulnetix tea distribution add $REL \
      --checksums checksums.txt \
      --base-url https://github.com/owner/repo/releases/download/v1.2.3

A channel with nothing to fetch — a package manager the user invokes — is a
distribution with a description and no URL:

    vulnetix tea distribution add $REL --description "Homebrew: brew install owner/tap/tool"

Each is idempotent on its URL, or on its description where there is no URL, so
re-running a release job updates the links rather than listing each of them
twice.`,
		Args: cobra.ExactArgs(1),
		RunE: runTeaDistributionAdd,
	}
	cmd.Flags().String("url", "", "direct download URL")
	cmd.Flags().String("description", "", "what this channel or format is")
	cmd.Flags().String("purl", "", "Package URL identifying this distribution specifically")
	cmd.Flags().String("sha256", "", "SHA-256 of the downloaded bytes")
	cmd.Flags().String("signature-url", "", "URL of the detached signature")
	cmd.Flags().String("checksums", "", "sha256sum-format manifest; one distribution per line")
	cmd.Flags().String("base-url", "", "URL each file in --checksums is served from")
	cmd.Flags().StringSlice("exclude", nil, "file name in --checksums to skip (repeatable)")
	return cmd
}

func runTeaDistributionAdd(cmd *cobra.Command, args []string) error {
	release := args[0]
	checksums, _ := cmd.Flags().GetString("checksums")

	var wanted []tea.Distribution
	if checksums != "" {
		base, _ := cmd.Flags().GetString("base-url")
		if base == "" {
			return fmt.Errorf("--checksums needs --base-url: a file name is not a download link, " +
				"and publishing one that does not resolve is worse than publishing nothing")
		}
		exclude, _ := cmd.Flags().GetStringSlice("exclude")
		parsed, err := distributionsFromChecksums(checksums, base, exclude)
		if err != nil {
			return err
		}
		wanted = parsed
	} else {
		d := tea.Distribution{
			URL:          strings.TrimSpace(mustFlag(cmd, "url")),
			Description:  strings.TrimSpace(mustFlag(cmd, "description")),
			SignatureURL: strings.TrimSpace(mustFlag(cmd, "signature-url")),
		}
		if purl := strings.TrimSpace(mustFlag(cmd, "purl")); purl != "" {
			d.Identifiers = append(d.Identifiers, tea.Identifier{IDType: "PURL", IDValue: purl})
		}
		if sum := strings.TrimSpace(mustFlag(cmd, "sha256")); sum != "" {
			d.Checksums = append(d.Checksums, tea.Checksum{AlgType: "SHA-256", AlgValue: sum})
		}
		if d.URL == "" && d.Description == "" {
			return fmt.Errorf("give at least --url or --description: a distribution with neither " +
				"gives a consumer nothing to act on")
		}
		wanted = []tea.Distribution{d}
	}

	ctx, cancel := teaContext(cmd)
	defer cancel()
	c := teaClient(cmd)

	published := make([]tea.Distribution, 0, len(wanted))
	for _, d := range wanted {
		out, err := c.CreateDistribution(ctx, release, d, teaDistributionKey(release, d))
		if err != nil {
			return teaFail(fmt.Errorf("publish %s: %w", distributionLabel(d), err))
		}
		published = append(published, *out)
	}

	if teaJSONFlag(cmd) {
		return teaPrintJSON(published)
	}
	for _, d := range published {
		printDistribution(d)
	}
	return nil
}

func newTeaDistributionListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list <component-release-uuid>",
		Short: "Show where a release can currently be obtained",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			detail, err := teaClient(cmd).ComponentRelease(ctx, args[0])
			if err != nil {
				return teaFail(err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(detail.Release.Distributions)
			}
			if len(detail.Release.Distributions) == 0 {
				fmt.Fprintln(os.Stderr, "No distributions published: a consumer resolving this release "+
					"can read its evidence but cannot obtain it.")
				return nil
			}
			for _, d := range detail.Release.Distributions {
				printDistribution(d)
			}
			return nil
		},
	}
}

func newTeaDistributionRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <distribution-uuid>",
		Aliases: []string{"rm"},
		Short:   "Withdraw a download link",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()
			if err := teaClient(cmd).DeleteDistribution(ctx, args[0]); err != nil {
				return teaFail(err)
			}
			fmt.Fprintln(os.Stderr, "Withdrawn. The file itself is untouched, and anyone who already "+
				"has the link still has it.")
			return nil
		},
	}
}

// ── Shared helpers ──────────────────────────────────────────────────────────

func mustFlag(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

// distributionsFromChecksums turns a sha256sum manifest into one distribution
// per file.
//
// Release pipelines already produce this file — it is what a user verifies a
// download against — so publishing distributions from it means the checksum a
// consumer reads through TEA and the checksum the project published are the
// same string, not two independently-computed ones that might disagree.
//
// The format is `<64 hex>␣␣<name>`, GNU coreutils' text/binary marker included.
// Anything that does not parse is refused rather than skipped: a manifest we
// only half understand would publish a partial set of links while looking
// complete.
func distributionsFromChecksums(path0, baseURL string, exclude []string) ([]tea.Distribution, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/")
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("--base-url %q is not an absolute URL", baseURL)
	}

	f, err := os.Open(path0)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path0, err)
	}
	defer f.Close()

	skip := map[string]bool{}
	for _, e := range exclude {
		skip[strings.TrimSpace(e)] = true
	}

	var out []tea.Distribution
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		digest, name, ok := strings.Cut(text, " ")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected `<sha256>  <file>`, got %q", path0, line, text)
		}
		// coreutils writes two spaces for text mode and ` *` for binary.
		name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "*"))
		if len(digest) != 64 || strings.Trim(digest, "0123456789abcdefABCDEF") != "" {
			return nil, fmt.Errorf("%s:%d: %q is not a SHA-256", path0, line, digest)
		}
		if name == "" || skip[name] {
			continue
		}
		// The manifest lists itself in some pipelines; a checksum file is not a
		// distribution of the software.
		if name == path.Base(path0) {
			continue
		}
		out = append(out, tea.Distribution{
			URL:         base.JoinPath(name).String(),
			Description: name,
			Checksums:   []tea.Checksum{{AlgType: "SHA-256", AlgValue: strings.ToLower(digest)}},
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path0, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s listed no files", path0)
	}
	return out, nil
}

// teaDistributionKey is the Idempotency-Key for publishing one distribution.
// It mirrors what the server derives the UUID from, so a retried pipeline step
// is recognised as a repeat rather than treated as a second download link.
func teaDistributionKey(release string, d tea.Distribution) string {
	if d.URL != "" {
		return "cli-distribution-" + release + "#" + d.URL
	}
	return "cli-distribution-" + release + "#desc:" + d.Description
}

func distributionLabel(d tea.Distribution) string {
	if d.URL != "" {
		return d.URL
	}
	return d.Description
}

func printDistribution(d tea.Distribution) {
	fmt.Printf("%s  %s\n", d.DistributionID, d.Description)
	if d.URL != "" {
		fmt.Printf("    url        %s\n", d.URL)
	}
	if d.SignatureURL != "" {
		fmt.Printf("    signature  %s\n", d.SignatureURL)
	}
	for _, s := range d.Checksums {
		fmt.Printf("    %-10s %s\n", strings.ToLower(s.AlgType), s.AlgValue)
	}
	for _, id := range d.Identifiers {
		fmt.Printf("    %-10s %s\n", strings.ToLower(id.IDType), id.IDValue)
	}
}

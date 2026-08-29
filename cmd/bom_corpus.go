package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/bom"
	"github.com/vulnetix/cli/v3/internal/display"
)

// ─────────────────────────────────────────────────────────────────────────
// bom_corpus.go — questions across a set of SBOMs rather than within one.
//
// A repository scan holds one document and can say what is in it. It cannot say
// which of the organisation's services carry a vulnerable package, or where a
// component sits at four different versions, because those are facts about a
// corpus. These commands answer them from documents already on disk, with no
// store and no server.
//
// The bigger version of the same question — across every repository, over time —
// is what the deployment labels push to the Vulnetix backend
// (internal/cdx/deployment.go). This is the part a CLI can honestly do.
//
// Everything here builds its index through runBOMCorpus, which reads documents
// via the same internal/bom loader `bom import` uses, so an SPDX document or an
// attestation-wrapped one is queryable exactly like a bare CycloneDX file.
// ─────────────────────────────────────────────────────────────────────────

// BOMCorpusOptions is the options struct for building a corpus index.
type BOMCorpusOptions struct {
	// Paths are the files, directories or globs to read.
	Paths []string
	// Recursive walks directories to any depth.
	Recursive bool
	// MaxDepth bounds a recursive walk; zero means unlimited.
	MaxDepth int
}

// BOMCorpusResult is a built index plus what it could not read.
type BOMCorpusResult struct {
	Index     *bom.Index
	Collected *bom.Collected
}

// runBOMCorpus collects documents and indexes them.
//
// The shared entry point for every corpus query, so they all agree about what
// is in the corpus and all report the same unreadable files.
func runBOMCorpus(opts BOMCorpusOptions) (*BOMCorpusResult, error) {
	collected, err := bom.Collect(bom.CollectOptions{
		Paths: opts.Paths, Recursive: opts.Recursive, MaxDepth: opts.MaxDepth,
	})
	if err != nil {
		return nil, err
	}
	if len(collected.Documents) == 0 {
		return nil, fmt.Errorf("no SBOM documents found in %s", strings.Join(opts.Paths, ", "))
	}
	return &BOMCorpusResult{Index: bom.NewIndex(collected.Documents), Collected: collected}, nil
}

// corpusFromCommand builds the corpus from a command's --from flags.
func corpusFromCommand(cmd *cobra.Command) (*BOMCorpusResult, error) {
	paths, _ := cmd.Flags().GetStringArray("from")
	recursive, _ := cmd.Flags().GetBool("recursive")
	depth, _ := cmd.Flags().GetInt("depth")
	if len(paths) == 0 {
		return nil, fmt.Errorf("--from is required: pass one or more files, directories or globs")
	}
	return runBOMCorpus(BOMCorpusOptions{Paths: paths, Recursive: recursive, MaxDepth: depth})
}

// reportCorpusGaps warns about documents that could not be read.
//
// A corpus query that silently answered from fewer documents than the user
// pointed at would turn "no results" into a wrong answer, so a failure is always
// surfaced even when the query itself succeeded.
func reportCorpusGaps(res *BOMCorpusResult) {
	if len(res.Collected.Failed) == 0 {
		return
	}
	term := display.NewTerminal()
	// Phrased without a verb that has to agree in number, so one failure and
	// five read equally well.
	fmt.Printf("%s %s could not be read — excluded from this answer:\n",
		display.WarningMark(term),
		pluralise("document", len(res.Collected.Failed)))
	for _, f := range res.Collected.Failed {
		fmt.Printf("    %s: %s\n", f.Path, display.Muted(term, f.Reason))
	}
	fmt.Println()
}

// ── ls ──────────────────────────────────────────────────────────────────────

var bomLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the SBOM documents in a corpus",
	Long: `List every SBOM document under the given paths.

Shows what each describes, in which format, how many components and
vulnerabilities it carries, and the deployment labels it was tagged with — so a
directory of documents becomes an inventory rather than a directory listing.

Examples:
  vulnetix bom ls --from ./sboms/
  vulnetix bom ls --from ./sboms/ --recursive
  vulnetix bom ls --from 'releases/*.cdx.json' -o json`,
	RunE:         runBOMLs,
	SilenceUsage: true,
}

func runBOMLs(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	res, err := corpusFromCommand(cmd)
	if err != nil {
		return err
	}
	summaries := res.Index.Summaries()

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		return emitJSON(map[string]any{
			"documents": summaries,
			"skipped":   res.Collected.Skipped,
			"failed":    res.Collected.Failed,
		})
	}

	term := display.NewTerminal()
	fmt.Println(display.Header(term, "SBOM corpus"))
	fmt.Println()
	reportCorpusGaps(res)

	rows := make([][]string, 0, len(summaries))
	for _, s := range summaries {
		label := string(s.Format)
		if s.SpecVersion != "" {
			label += " " + s.SpecVersion
		}
		rows = append(rows, []string{
			sourceName(s.Path),
			orDash(preferLabel(s.Subject, "")),
			orDash(s.Version),
			label,
			fmt.Sprintf("%d", s.Components),
			fmt.Sprintf("%d", s.Vulnerabilities),
			orDash(s.Deployment.String()),
		})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Document", MinWidth: 22, MaxWidth: 34},
		{Header: "Subject", MinWidth: 18, MaxWidth: 28},
		{Header: "Version", MinWidth: 10},
		{Header: "Format", MinWidth: 16},
		{Header: "Components", Align: display.AlignRight, MinWidth: 10},
		{Header: "Vulns", Align: display.AlignRight, MinWidth: 6},
		{Header: "Deployment"},
	}, rows))
	fmt.Print("\n\n")
	fmt.Println(display.Muted(term, fmt.Sprintf("%s in the corpus", pluralise("document", len(summaries)))))
	return nil
}

// ── where ───────────────────────────────────────────────────────────────────

var bomWhereCmd = &cobra.Command{
	Use:   "where <package>",
	Short: "Find which documents contain a package",
	Long: `Find every document in a corpus that contains a package — the blast radius.

Accepts a purl (with or without a version), a bare name, or a substring. Reports
each document, the version it carries, and whether the dependency is direct
there — which is where the version can actually be changed.

Directness is reported as unknown, not false, when a document has no dependency
graph to answer from. A confident wrong answer about where a package can be
fixed is worse than an honest gap.

--fail-on-found makes this a CI gate: exit non-zero when the package is present
at all, for the case where its presence is itself the problem.

Examples:
  vulnetix bom where lodash --from ./sboms/
  vulnetix bom where pkg:golang/github.com/hashicorp/golang-lru --from ./sboms/
  vulnetix bom where log4j-core --from ./sboms/ --fail-on-found
  vulnetix bom where lodash --from ./sboms/ -o json`,
	Args:         cobra.ExactArgs(1),
	RunE:         runBOMWhere,
	SilenceUsage: true,
}

func runBOMWhere(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	failOnFound, _ := cmd.Flags().GetBool("fail-on-found")

	res, err := corpusFromCommand(cmd)
	if err != nil {
		return err
	}
	br := res.Index.Where(args[0])

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		if err := emitJSON(br); err != nil {
			return err
		}
	} else {
		renderBlastRadius(res, br)
	}

	if failOnFound && len(br.Locations) > 0 {
		return &bomGateError{
			gate: "bom-where",
			message: fmt.Sprintf("%s found in %s",
				preferLabel(br.Name, br.Query), pluralise("document", len(br.Locations))),
		}
	}
	return nil
}

func renderBlastRadius(res *BOMCorpusResult, br *bom.BlastRadius) {
	term := display.NewTerminal()

	fmt.Println(display.Header(term, "Blast radius"))
	fmt.Println()
	reportCorpusGaps(res)

	if len(br.Locations) == 0 {
		fmt.Printf("%s %s is not present in any document in this corpus.\n",
			display.CheckMark(term), display.Bold(term, br.Query))
		return
	}

	fmt.Printf("%s  %s\n", display.Bold(term, preferLabel(br.Name, br.Query)),
		display.Muted(term, br.Key))
	fmt.Printf("%s at %s\n\n",
		pluralise("version", len(br.Versions)),
		strings.Join(br.Versions, ", "))

	rows := make([][]string, 0, len(br.Locations))
	for _, l := range br.Locations {
		rows = append(rows, []string{
			sourceName(l.Path), orDash(l.Subject), l.Version,
			directnessCell(l.Direct), orDash(l.Deployment.String()),
		})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Document", MinWidth: 22, MaxWidth: 34},
		{Header: "Subject", MinWidth: 18, MaxWidth: 28},
		{Header: "Version", MinWidth: 14},
		{Header: "Dependency", MinWidth: 12},
		{Header: "Deployment"},
	}, rows))
	fmt.Print("\n\n")

	summary := fmt.Sprintf("%s · %d direct · %d transitive",
		pluralise("document", len(br.Locations)), br.DirectCount, br.TransitiveCount)
	if br.UnknownCount > 0 {
		summary += fmt.Sprintf(" · %d unknown (no dependency graph)", br.UnknownCount)
	}
	fmt.Println(display.Bold(term, summary))
}

// directnessCell renders directness, which is null when unmeasurable.
func directnessCell(direct *bool) string {
	switch {
	case direct == nil:
		return "unknown"
	case *direct:
		return "direct"
	default:
		return "transitive"
	}
}

// ── skew ────────────────────────────────────────────────────────────────────

var bomSkewCmd = &cobra.Command{
	Use:   "skew",
	Short: "Find packages at inconsistent versions across a corpus",
	Long: `Report packages present at more than one version across the corpus.

This is the "why do we have five versions of the same library" question, and it
usually has an actionable answer: a package at four versions across six services
is normally four upgrades nobody sequenced, not four deliberate pins.

Most-divergent first, with the documents carrying each version, and a count of
how many carry it as a direct dependency — which is where the version can
actually be changed.

--fail-on-count gates CI on the number of skewed packages.

Examples:
  vulnetix bom skew --from ./sboms/
  vulnetix bom skew --from ./sboms/ --min-versions 3
  vulnetix bom skew --from ./sboms/ --fail-on-count 0
  vulnetix bom skew --from ./sboms/ -o json`,
	RunE:         runBOMSkew,
	SilenceUsage: true,
}

func runBOMSkew(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	minVersions, _ := cmd.Flags().GetInt("min-versions")
	failOnCount, _ := cmd.Flags().GetInt("fail-on-count")

	res, err := corpusFromCommand(cmd)
	if err != nil {
		return err
	}

	entries := res.Index.Skew()
	if minVersions > 2 {
		filtered := entries[:0]
		for _, e := range entries {
			if len(e.Versions) >= minVersions {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		if err := emitJSON(map[string]any{
			"skew":      entries,
			"documents": len(res.Index.Documents()),
			"failed":    res.Collected.Failed,
		}); err != nil {
			return err
		}
	} else {
		renderSkew(res, entries)
	}

	// A negative threshold disables the gate; zero is a real threshold —
	// "no package may be at more than one version".
	if failOnCount >= 0 && len(entries) > failOnCount {
		return &bomGateError{
			gate: "bom-skew",
			message: fmt.Sprintf("%s at inconsistent versions exceeds the allowed %d",
				pluralise("package", len(entries)), failOnCount),
		}
	}
	return nil
}

func renderSkew(res *BOMCorpusResult, entries []bom.SkewEntry) {
	term := display.NewTerminal()

	fmt.Println(display.Header(term, "Version skew"))
	fmt.Println()
	reportCorpusGaps(res)

	if len(entries) == 0 {
		fmt.Printf("%s No package is at more than one version across %s.\n",
			display.CheckMark(term),
			pluralise("document", len(res.Index.Documents())))
		return
	}

	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		versions := make([]string, 0, len(e.Versions))
		for _, v := range e.Versions {
			versions = append(versions, fmt.Sprintf("%s (%d)", v.Version, len(v.Documents)))
		}
		rows = append(rows, []string{
			e.Name,
			fmt.Sprintf("%d", len(e.Versions)),
			fmt.Sprintf("%d", e.DocumentCount),
			fmt.Sprintf("%d", e.DirectCount),
			strings.Join(versions, ", "),
		})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Package", MinWidth: 24, MaxWidth: 40},
		{Header: "Versions", Align: display.AlignRight, MinWidth: 8},
		{Header: "Documents", Align: display.AlignRight, MinWidth: 9},
		{Header: "Direct", Align: display.AlignRight, MinWidth: 6},
		{Header: "Versions present (documents)"},
	}, rows))
	fmt.Print("\n\n")
	fmt.Println(display.Bold(term, fmt.Sprintf(
		"%s at inconsistent versions across %s",
		pluralise("package", len(entries)),
		pluralise("document", len(res.Index.Documents())))))
}

// ── search ──────────────────────────────────────────────────────────────────

var bomSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search a corpus for packages, documents, vulnerabilities and licences",
	Long: `Search across every document in a corpus.

Four facets, each counted and limited independently, so a query matching a
thousand components still shows the one document and two vulnerabilities it also
matched rather than burying them.

Vulnerabilities match on identifier and on description, because "log4shell" is
how people refer to CVE-2021-44228 and an id-only search finds nothing for it.

Examples:
  vulnetix bom search lodash --from ./sboms/
  vulnetix bom search log4shell --from ./sboms/
  vulnetix bom search AGPL --from ./sboms/ --limit 50
  vulnetix bom search payment --from ./sboms/ -o json`,
	Args:         cobra.ExactArgs(1),
	RunE:         runBOMSearch,
	SilenceUsage: true,
}

func runBOMSearch(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	limit, _ := cmd.Flags().GetInt("limit")

	query := strings.TrimSpace(args[0])
	if len(query) < bom.MinSearchQuery {
		return fmt.Errorf("search query must be at least %d characters; a shorter one matches most of the corpus",
			bom.MinSearchQuery)
	}

	res, err := corpusFromCommand(cmd)
	if err != nil {
		return err
	}
	hits := res.Index.Search(query, limit)

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		return emitJSON(hits)
	}
	renderSearch(res, hits)
	return nil
}

func renderSearch(res *BOMCorpusResult, hits *bom.SearchResults) {
	term := display.NewTerminal()

	fmt.Println(display.Header(term, "Corpus search"))
	fmt.Println()
	reportCorpusGaps(res)

	total := hits.Totals["components"] + hits.Totals["documents"] +
		hits.Totals["vulnerabilities"] + hits.Totals["licenses"]
	if total == 0 {
		fmt.Printf("%s Nothing matched %s.\n", display.WarningMark(term), display.Bold(term, hits.Query))
		return
	}

	if len(hits.Components) > 0 {
		fmt.Println(display.Subheader(term, facetHeading("Components", len(hits.Components), hits.Totals["components"])))
		rows := make([][]string, 0, len(hits.Components))
		for _, c := range hits.Components {
			rows = append(rows, []string{
				c.Name, strings.Join(c.Versions, ", "), fmt.Sprintf("%d", c.Documents),
			})
		}
		fmt.Print(display.Table(term, []display.Column{
			{Header: "Package", MinWidth: 26, MaxWidth: 40},
			{Header: "Versions", MinWidth: 24, MaxWidth: 44},
			{Header: "Documents", Align: display.AlignRight, MinWidth: 9},
		}, rows))
		fmt.Print("\n\n")
	}

	if len(hits.Documents) > 0 {
		fmt.Println(display.Subheader(term, facetHeading("Documents", len(hits.Documents), hits.Totals["documents"])))
		rows := make([][]string, 0, len(hits.Documents))
		for _, d := range hits.Documents {
			rows = append(rows, []string{
				sourceName(d.Path), orDash(d.Subject), orDash(d.Version),
				fmt.Sprintf("%d", d.Components),
			})
		}
		fmt.Print(display.Table(term, []display.Column{
			{Header: "Document", MinWidth: 24, MaxWidth: 36},
			{Header: "Subject", MinWidth: 20, MaxWidth: 30},
			{Header: "Version", MinWidth: 10},
			{Header: "Components", Align: display.AlignRight, MinWidth: 10},
		}, rows))
		fmt.Print("\n\n")
	}

	if len(hits.Vulnerabilities) > 0 {
		fmt.Println(display.Subheader(term, facetHeading("Vulnerabilities", len(hits.Vulnerabilities), hits.Totals["vulnerabilities"])))
		rows := make([][]string, 0, len(hits.Vulnerabilities))
		for _, v := range hits.Vulnerabilities {
			rows = append(rows, []string{
				v.ID, orDash(v.Severity), fmt.Sprintf("%d", len(v.Documents)),
			})
		}
		fmt.Print(display.Table(term, []display.Column{
			{Header: "ID", MinWidth: 24, MaxWidth: 34},
			{Header: "Severity", MinWidth: 10, Color: bomSeverityColour(term)},
			{Header: "Documents", Align: display.AlignRight, MinWidth: 9},
		}, rows))
		fmt.Print("\n\n")
	}

	if len(hits.Licenses) > 0 {
		fmt.Println(display.Subheader(term, facetHeading("Licences", len(hits.Licenses), hits.Totals["licenses"])))
		rows := make([][]string, 0, len(hits.Licenses))
		for _, l := range hits.Licenses {
			rows = append(rows, []string{l.License, fmt.Sprintf("%d", l.Components)})
		}
		fmt.Print(display.Table(term, []display.Column{
			{Header: "Licence", MinWidth: 26, MaxWidth: 44},
			{Header: "Components", Align: display.AlignRight, MinWidth: 10},
		}, rows))
		fmt.Print("\n\n")
	}
}

// facetHeading names a facet and says when it was truncated.
func facetHeading(name string, shown, total int) string {
	if total > shown {
		return fmt.Sprintf("%s (%d of %d — raise --limit for the rest)", name, shown, total)
	}
	return fmt.Sprintf("%s (%d)", name, total)
}

// ── flags ───────────────────────────────────────────────────────────────────

func init() {
	bomCmd.AddCommand(bomLsCmd, bomWhereCmd, bomSkewCmd, bomSearchCmd)

	for _, c := range []*cobra.Command{bomLsCmd, bomWhereCmd, bomSkewCmd, bomSearchCmd} {
		c.Flags().StringArray("from", nil, "File, directory or glob to read SBOMs from (repeatable)")
		c.Flags().Bool("recursive", false, "Walk directories to any depth")
		c.Flags().Int("depth", 0, "Maximum directory depth when recursive (0 = unlimited)")
		c.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")
	}

	bomWhereCmd.Flags().Bool("fail-on-found", false, "Exit non-zero when the package is present in any document")

	bomSkewCmd.Flags().Int("min-versions", 2, "Only report packages present at this many versions or more")
	bomSkewCmd.Flags().Int("fail-on-count", -1, "Exit non-zero when more than this many packages are skewed (-1 disables)")

	bomSearchCmd.Flags().Int("limit", 25, "Maximum results per facet")
}

package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// The EOL endpoints have backed --block-eol since it landed and are documented
// in full — response fields and all — in website/content/docs/cli-reference/vdb.md,
// but no subcommand ever exposed them, so every documented example failed with
// "unknown command". These are read-only wrappers over the client methods the
// gate already uses.

var eolCmd = &cobra.Command{
	Use:   "eol",
	Short: "Query end-of-life lifecycle data for products and releases",
	Long: `Query the VDB end-of-life database.

This is the same lifecycle data the --block-eol quality gate reads, exposed for
lookups and for working out what a gate will do before you turn it on.

Examples:
  vulnetix vdb eol product nodejs
  vulnetix vdb eol release nodejs 18`,
}

var eolProductCmd = &cobra.Command{
	Use:   "product <product>",
	Short: "Lifecycle data for a product and all its releases",
	Long: `Retrieve end-of-life lifecycle data for a product — a runtime, a framework,
a distribution — and every release the EOL database tracks for it.

Examples:
  vulnetix vdb eol product nodejs
  vulnetix vdb eol product python -o json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		product := args[0]

		vdbLog(cmd).Infof("Fetching EOL lifecycle for %s...", product)

		result, err := client.EOLProduct(product)
		if err != nil {
			return fmt.Errorf("failed to get EOL product: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("eol-product", product)

		return vdbRender(cmd, result, renderEOLProduct)
	},
}

var eolReleaseCmd = &cobra.Command{
	Use:   "release <product> <release>",
	Short: "Lifecycle data for one release of a product",
	Long: `Retrieve end-of-life lifecycle data for a single release.

This is the exact record --block-eol grades a detected runtime pin against, so
it is the way to see what the gate will decide before you enable it.

Examples:
  vulnetix vdb eol release nodejs 18
  vulnetix vdb eol release python 3.8 -o json`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client := newVDBClient()
		product, release := args[0], args[1]

		vdbLog(cmd).Infof("Fetching EOL lifecycle for %s %s...", product, release)

		result, err := client.EOLRelease(product, release)
		if err != nil {
			return fmt.Errorf("failed to get EOL release: %w", err)
		}
		printRateLimit(client)
		recordVDBQuery("eol-release", product+"/"+release)

		return vdbRender(cmd, result, renderEOLRelease)
	},
}

// renderEOLProduct prints a product and its releases as a lifecycle table.
func renderEOLProduct(data any, ctx *display.Context) string {
	resp, ok := data.(*vdb.EOLProductResponse)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	b.WriteString(display.Header(t, "EOL Lifecycle: "+resp.Product.Label))
	pairs := []display.KVPair{
		{Key: "Name", Value: resp.Product.Name},
		{Key: "Category", Value: resp.Product.Category},
	}
	if len(resp.Product.Tags) > 0 {
		pairs = append(pairs, display.KVPair{Key: "Tags", Value: strings.Join(resp.Product.Tags, ", ")})
	}
	b.WriteString("\n" + display.KeyValue(t, pairs) + "\n\n")

	cols := []display.Column{
		{Header: "RELEASE"}, {Header: "RELEASED"}, {Header: "LTS"},
		{Header: "EOL"}, {Header: "EOL FROM"}, {Header: "MAINTAINED"}, {Header: "LATEST"},
	}
	rows := make([][]string, 0, len(resp.Product.Releases))
	for _, r := range resp.Product.Releases {
		rows = append(rows, []string{
			r.Name,
			eolStr(r.ReleaseDate),
			yesNo(r.IsLts),
			yesNo(r.IsEol),
			eolStr(r.EolFrom),
			yesNo(r.IsMaintained),
			eolStr(r.LatestVersion()),
		})
	}
	b.WriteString(display.Table(t, cols, rows))
	return strings.TrimRight(b.String(), "\n")
}

// renderEOLRelease prints one release's lifecycle record.
func renderEOLRelease(data any, ctx *display.Context) string {
	resp, ok := data.(*vdb.EOLReleaseResponse)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	r := resp.Release
	var b strings.Builder

	b.WriteString(display.Header(t, "EOL Lifecycle: "+resp.ProductName+" "+r.Name))
	pairs := []display.KVPair{
		{Key: "Release", Value: r.Label},
		{Key: "Released", Value: eolStr(r.ReleaseDate)},
		{Key: "LTS", Value: yesNo(r.IsLts)},
		{Key: "End of life", Value: yesNo(r.IsEol)},
		{Key: "EOL from", Value: eolStr(r.EolFrom)},
		{Key: "End of active support", Value: yesNo(r.IsEoas)},
		{Key: "EOAS from", Value: eolStr(r.EoasFrom)},
		{Key: "Maintained", Value: yesNo(r.IsMaintained)},
		{Key: "Latest version", Value: eolStr(r.LatestVersion())},
		{Key: "Latest date", Value: eolStr(r.LatestDate())},
	}
	b.WriteString("\n" + display.KeyValue(t, pairs))
	return strings.TrimRight(b.String(), "\n")
}

// eolStr renders an optional string field, which the EOL feed leaves null for
// anything it does not know rather than guessing.
func eolStr(s *string) string {
	if s == nil || *s == "" {
		return "—"
	}
	return *s
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func init() {
	eolCmd.AddCommand(eolProductCmd)
	eolCmd.AddCommand(eolReleaseCmd)
	vdbCmd.AddCommand(eolCmd)
}

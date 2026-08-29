package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/triage"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// bom_enrich_vdb.go — the network half of enrichment, kept apart from the file
// half so the pure transformations stay testable without a server.

// attachVDBVulnerabilities queries the VDB for a document's purls and merges
// the resulting vulnerability entries into it.
//
// The request carries an Attribution, which is the existing mechanism for "an
// SBOM the CLI relayed rather than generated". Without it the server would
// record these findings as though this CLI had discovered them, which would
// misattribute a third-party tool's inventory to a Vulnetix scan.
func attachVDBVulnerabilities(cmd *cobra.Command, b *cdx.BOM, purls []string) error {
	client := newCliClient()
	if client == nil {
		return fmt.Errorf("not authenticated; run 'vulnetix auth login' or pass --no-vulns")
	}

	ctx, cancel := context.WithTimeout(cmdContextFor(cmd), 180*time.Second)
	defer cancel()

	resp, err := client.CliSCAWithContext(ctx, envForCli(), vdb.CliSCARequest{
		Purls: purls,
		Attribution: &vdb.CliToolAttribution{
			ToolName:    enrichmentToolName(b),
			ToolVersion: enrichmentToolVersion(b),
		},
	})
	if err != nil {
		return err
	}
	if resp == nil || resp.Data.CycloneDX == nil {
		return fmt.Errorf("the VDB returned no document")
	}

	// MergeUpstream is the existing purl-keyed merge: local data wins on field
	// conflicts, upstream fills gaps and contributes vulnerabilities with their
	// affects[] rewritten onto local bom-refs. Reusing it is what keeps an
	// enriched document's graph traversable — and it takes the server's raw map
	// directly, so nothing is narrowed through the internal model on the way in.
	merged, err := cdx.MergeUpstream(b, resp.Data.CycloneDX)
	if err != nil {
		return err
	}
	*b = *merged
	return nil
}

// enrichmentToolName attributes the inventory to whoever produced it.
//
// The input document names its own generator in metadata.tools; carrying that
// through means the server records "syft found these packages, Vulnetix
// enriched them" rather than claiming the discovery.
func enrichmentToolName(b *cdx.BOM) string {
	if b.Metadata != nil && b.Metadata.Tools != nil && len(b.Metadata.Tools.Components) > 0 {
		if n := b.Metadata.Tools.Components[0].Name; n != "" {
			return n
		}
	}
	return "unknown-sbom-generator"
}

func enrichmentToolVersion(b *cdx.BOM) string {
	if b.Metadata != nil && b.Metadata.Tools != nil && len(b.Metadata.Tools.Components) > 0 {
		return b.Metadata.Tools.Components[0].Version
	}
	return ""
}

// cmdContextFor returns the command's context, or a background one.
func cmdContextFor(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

// cmdContext is the background context for calls with no command in scope.
func cmdContext() context.Context { return context.Background() }

// companionOpenVEX renders the applied statements as an OpenVEX document.
//
// Written beside the enriched SBOM so a consumer that wants the statements
// separately does not have to extract them from the analysis blocks. It goes
// through triage.GenerateOpenVEX — the CLI's one OpenVEX writer — rather than
// assembling the JSON here, so the companion document and every other VEX this
// CLI emits stay in the same shape.
func companionOpenVEX(statements []vexStatementForCompanion) ([]byte, error) {
	findings := make([]*triage.TriageFinding, 0, len(statements))
	for _, s := range statements {
		findings = append(findings, &triage.TriageFinding{
			CVEID:  s.VulnID,
			Status: s.Status,
			// The explanation names the document and the basis the statement
			// matched on, which is the part a consumer of the companion file
			// cannot reconstruct for themselves.
			ActionResponse: s.Explain,
		})
	}
	return triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{
		Author:  "Vulnetix",
		Tooling: "vulnetix-cli/" + version,
	})
}

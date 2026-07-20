package cmd

import (
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/testsuite"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// testConfigsToWire converts detected test-runner config files into the typed
// env metadata carried on the SAST submission (metadata only, no raw body).
func testConfigsToWire(configs []testsuite.Config) []vdb.CliTestConfigMetadata {
	if len(configs) == 0 {
		return nil
	}
	out := make([]vdb.CliTestConfigMetadata, 0, len(configs))
	for _, c := range configs {
		out = append(out, vdb.CliTestConfigMetadata{
			Path:        c.Path,
			Framework:   c.Framework,
			Language:    c.Language,
			ContentType: c.ContentType,
			SHA256:      c.SHA256,
			Size:        c.Size,
		})
	}
	return out
}

// suppressTestFindings removes findings attributed to the test suite from the
// report and returns a CliSuppressionMint per removed finding, so the backend
// records them as suppressed (analogous to nosec-driven suppressions) rather
// than as active findings. Only used when --suppress-test-code is set.
func suppressTestFindings(findings []sast.Finding, gitCtx *gitctx.GitContext) ([]sast.Finding, []vdb.CliSuppressionMint) {
	branch := ""
	if gitCtx != nil {
		branch = gitCtx.CurrentBranch
	}
	kept := make([]sast.Finding, 0, len(findings))
	var mints []vdb.CliSuppressionMint
	for _, f := range findings {
		if !f.IsTestSuite {
			kept = append(kept, f)
			continue
		}
		category := "sast"
		if f.Metadata != nil && f.Metadata.Kind != "" {
			category = f.Metadata.Kind
		}
		reason := "Located in test suite"
		if f.TestFramework != "" {
			reason += " (" + f.TestFramework + ")"
		}
		mints = append(mints, vdb.CliSuppressionMint{
			RuleID:          f.RuleID,
			Category:        category,
			SuppressionType: "test-code",
			Reason:          reason,
			FilePath:        f.ArtifactURI,
			LineNumber:      f.StartLine,
			CodeSnippet:     f.Snippet,
			BranchName:      branch,
			Origin:          "cli-test-code",
			Active:          true,
			Fingerprint:     f.Fingerprint,
		})
	}
	return kept, mints
}

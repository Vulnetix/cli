package cmd

// `vulnetix upload` publishes a scanner report through the same typed
// endpoints `vulnetix gha upload` uses.
//
// It used to POST every file to /v2/cli.upload, a blob endpoint vdb-api answers
// with HTTP 503 "file storage not configured" because it has no upload bucket.
// The command has therefore never recorded anything in production, and the
// failure was not obvious: the docs describe it as the way to get a
// third-party report into Vulnetix, and 49 tool tutorials ended with it.
//
// Routing through the typed endpoints means a report published from a laptop
// lands as the same ScannerRun, snapshot, findings, triage and VEX records as
// one published from CI, attributed to the tool that produced it.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Vulnetix/vdb-sca-match/sarif"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/upload"
)

// uploadPublishable reports whether a detected format has a typed endpoint.
func uploadPublishable(format string) bool {
	switch format {
	case "sarif", "cyclonedx", "spdx":
		return true
	}
	return false
}

// unsupportedFormatError explains why a file cannot be published and, where the
// producing tool has a SARIF mode, how to get one that can be.
//
// A bare "unsupported format" would send people back to the 503 they were
// already getting. Naming the tool's own SARIF flag is the actionable part.
func unsupportedFormatError(path, format string) error {
	base := filepath.Base(path)
	var b strings.Builder
	fmt.Fprintf(&b, "%s is not a format Vulnetix ingests (detected %q).\n", base, format)
	b.WriteString("Vulnetix accepts SARIF, CycloneDX and SPDX.")
	if hint := sarifExportHint(base); hint != "" {
		b.WriteString("\n" + hint)
	}
	return fmt.Errorf("%s", b.String())
}

// sarifExportHint names the flag that makes a tool emit SARIF, keyed on the
// filenames its own documentation tells people to use.
var sarifExportHints = []struct {
	match string
	hint  string
}{
	{"sonarqube", "SonarQube can emit SARIF: use its sonar.sarifReportPaths export."},
	{"sonarcloud", "SonarCloud can emit SARIF: use its sonar.sarifReportPaths export."},
	{"snyk", "Snyk emits SARIF with --sarif-file-output=<file>."},
	{"trufflehog", "TruffleHog emits SARIF with --json then a converter, or use gitleaks --report-format sarif."},
	{"semgrep", "Semgrep emits SARIF with --sarif --sarif-output=<file>."},
	{"trivy", "Trivy emits SARIF with --format sarif --output <file>."},
	{"grype", "Grype emits SARIF with -o sarif=<file>."},
	{"checkov", "Checkov emits SARIF with -o sarif."},
	{"zap", "ZAP emits SARIF through its SARIF report add-on."},
	{"retire", "retire.js emits SARIF with --outputformat sarif."},
	{"rubocop", "RuboCop emits SARIF via the rubocop-sarif formatter."},
	{"shellcheck", "ShellCheck emits SARIF with -f sarif (v0.10+)."},
	{"pylint", "Pylint emits SARIF via pylint-sarif."},
	{"swiftlint", "SwiftLint emits SARIF with --reporter sarif."},
	{"xray", "JFrog Xray emits SARIF with --format sarif on jf scan."},
	{"phylum", "Phylum emits SARIF with --format sarif."},
	{"nikto", "Nikto has no SARIF mode; publish a CycloneDX or SARIF report from another scanner instead."},
	{"openvas", "OpenVAS has no SARIF mode; publish a CycloneDX or SARIF report from another scanner instead."},
	{"qualys", "Qualys has no SARIF mode; use its CycloneDX SBOM export instead."},

	// The rest of the catalog's SARIF-capable tools, keyed on the output
	// filename each one's own documentation uses. A tool whose native JSON is
	// uploaded by mistake is the common case, and naming its SARIF flag is the
	// difference between "unsupported format" and a working scan.
	{"bandit", "Bandit emits SARIF with -f sarif (bandit-sarif-formatter installed)."},
	{"brakeman", "Brakeman emits SARIF with -f sarif."},
	{"gitleaks", "Gitleaks emits SARIF with --report-format sarif --report-path <file>."},
	{"osv", "OSV-Scanner emits SARIF with --format sarif --output <file>."},
	{"dependency-check", "OWASP Dependency-Check emits SARIF with --format SARIF."},
	{"hadolint", "hadolint emits SARIF with --format sarif."},
	{"dockle", "Dockle emits SARIF with -f sarif -o <file>."},
	{"kubescape", "Kubescape emits SARIF with --format sarif --output <file>."},
	{"kics", "KICS emits SARIF with --report-formats sarif."},
	{"terrascan", "Terrascan emits SARIF with -o sarif."},
	{"tfsec", "tfsec emits SARIF with --format sarif; newer builds are `trivy config`."},
	{"conftest", "Conftest emits SARIF with --output sarif."},
	{"gosec", "gosec emits SARIF with -fmt sarif -out <file>."},
	{"govulncheck", "govulncheck emits SARIF with -format sarif."},
	{"golangci", "golangci-lint emits SARIF with --out-format sarif."},
	{"clippy", "Clippy emits SARIF through clippy-sarif (cargo clippy --message-format=json | clippy-sarif)."},
	{"cppcheck", "cppcheck emits SARIF with --output-format=sarif (2.13+)."},
	{"flawfinder", "Flawfinder emits SARIF with --sarif."},
	{"devskim", "DevSkim emits SARIF with -f sarif -O <file>."},
	{"detekt", "detekt emits SARIF with --report sarif:<file>."},
	{"psalm", "Psalm emits SARIF with --report=<file>.sarif."},
	{"phpstan", "PHPStan emits SARIF with --error-format=sarif."},
	{"spotbugs", "SpotBugs emits SARIF with -sarif (4.5+)."},
	{"njsscan", "njsscan emits SARIF with --sarif -o <file>."},
	{"mobsfscan", "mobsfscan emits SARIF with --sarif -o <file>."},
	{"nuclei", "Nuclei emits SARIF with -sarif-export <file>."},
	{"prowler", "Prowler emits SARIF with -M sarif."},
	{"stylelint", "Stylelint emits SARIF via stylelint-sarif-formatter."},
	{"biome", "Biome emits SARIF with --reporter=gitlab piped through a converter, or use its GitHub reporter."},
	{"cdxgen", "cdxgen writes CycloneDX already; publish the .cdx.json it produced rather than a converted file."},
	{"syft", "Syft writes CycloneDX or SPDX already; publish with -o cyclonedx-json=<file>."},
}

func sarifExportHint(fileName string) string {
	n := strings.ToLower(fileName)
	for _, h := range sarifExportHints {
		if strings.Contains(n, h.match) {
			return h.hint
		}
	}
	return ""
}

// alreadyPublishedError is returned for a report Vulnetix's own scanners wrote.
//
// Publishing one through the third-party route would mint a second ScannerRun
// for a scan that is already recorded, doubling its findings. The subcommand
// that produced the file published it when it ran.
func alreadyPublishedError(path, toolName string) error {
	return fmt.Errorf(
		"%s was produced by %s, which published it when it ran.\n"+
			"Re-publishing it here would record the same scan twice.\n"+
			"If that run was offline or used --no-upload, re-run the scan while authenticated.",
		filepath.Base(path), toolName)
}

// newUploadSubmitter builds the publisher `upload` shares with `gha upload`.
func newUploadSubmitter(ctx context.Context, dctx *display.Context, dryRun bool) (*ghaSubmitter, error) {
	client := newCliClient()
	if client == nil {
		return nil, fmt.Errorf("authentication required: run 'vulnetix auth login' first")
	}
	return &ghaSubmitter{
		client: client,
		env:    envForCliWithGit(nil),
		ctx:    ctx,
		dryRun: dryRun,
		logf:   func(format string, args ...any) { dctx.Logger.Infof(format, args...) },
		warnf:  func(format string, args ...any) { dctx.Logger.Warnf(format, args...) },
	}, nil
}

// publishLocalFile publishes one report, using the file's own basename as the
// category hint. Outside a workflow there is no artifact name to go on, and the
// basename is what carries the distinction between "trivy-fs" and
// "trivy-config".
func publishLocalFile(s *ghaSubmitter, path string) (ghaFileResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ghaFileResult{}, fmt.Errorf("read %s: %w", path, err)
	}

	format := upload.DetectFormat(path, data)
	if !uploadPublishable(format) {
		return ghaFileResult{}, unsupportedFormatError(path, format)
	}

	// Refuse Vulnetix's own reports before sending anything.
	if format == "sarif" {
		if log, rep := sarif.ValidateBytes(data, ghaMaxResults); !rep.HasErrors() && log != nil {
			for _, run := range log.Runs {
				if name := sarif.ToolOf(run).Name; isVulnetixOwnTool(name) {
					return ghaFileResult{}, alreadyPublishedError(path, name)
				}
			}
		}
	}

	hint := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	res := s.publishFile(hint, path)
	if res.Status == "error" {
		return res, fmt.Errorf("%s: %s", filepath.Base(path), res.Error)
	}
	return res, nil
}

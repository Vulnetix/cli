package cmd

import (
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
)

// pullCliRules was the pre-scan rule-pack pre-fetch path. After Phase-2 the
// matching /v2/cli.<probe> endpoints are persistence-only (they accept the
// SARIF doc + findings and write SARIFInfo / SarifResults / Finding / Triage
// rows). Rule packs are now strictly embedded; the call sites remain so we
// can re-introduce server-pushed rules in a future iteration without touching
// every subcommand. Today this is a no-op.
func pullCliRules(probe string, payload any) {
	_ = probe
	_ = payload
}

// scaCmd runs a scan with only SCA enabled.
var scaCmd = &cobra.Command{
	Use:   "sca",
	Short: "Run only Software Composition Analysis (SCA) scan",
	Long: `Run a scan with only SCA enabled. Equivalent to:
  vulnetix scan --evaluate-sca --no-licenses --no-sast --no-containers --no-secrets --no-iac

Performs vulnerability analysis on package dependencies only, without running
SAST, license analysis, secret detection, container analysis, or IaC analysis.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initDisplayContext(cmd, display.ModeText)
		// Credentials are optional — community fallback is used when absent.
		// But when the user IS authenticated (Pro subscription), this is
		// what populates vdbCreds so the cli.sca call goes out under
		// their plan rather than the embedded community fallback.
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// SCA fan-out happens inside runScanWithFeatures → tryCliSCA, no
		// pre-pull needed here.
		return runScanWithFeatures(cmd.Context(), cmd,
			true,  // noSAST
			false, // noSCA
			true,  // noLicenses
			true,  // noSecrets
			true,  // noContainers
			true,  // noIAC
		)
	},
}

// sastCmd runs a scan with only SAST enabled.
var sastCmd = &cobra.Command{
	Use:   "sast",
	Short: "Run only Static Application Security Testing (SAST) scan",
	Long: `Run a scan with only SAST enabled. Equivalent to:
  vulnetix scan --evaluate-sast --no-licenses --no-sca --no-containers --no-secrets --no-iac

Performs static code analysis for security vulnerabilities only, without
analyzing package dependencies, licenses, secrets, containers, or IaC.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initDisplayContext(cmd, display.ModeText)
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		pullCliRules("sast", map[string]any{"languages": []string{}, "policy_set": ""})
		return runScanWithFeatures(cmd.Context(), cmd,
			false, // noSAST
			true,  // noSCA
			true,  // noLicenses
			true,  // noSecrets
			true,  // noContainers
			true,  // noIAC
		)
	},
}

// secretsCmd runs a scan with only secret detection enabled.
var secretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Run only secret detection scan",
	Long: `Run a scan with only secret detection enabled. Equivalent to:
  vulnetix scan --evaluate-secrets --no-licenses --no-sast --no-sca --no-containers --no-iac

Detects hardcoded secrets (API keys, passwords, tokens, etc.) in source code
only, without analyzing package dependencies, licenses, or other issues.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initDisplayContext(cmd, display.ModeText)
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		pullCliRules("secrets", map[string]any{"policy_set": ""})
		return runScanWithFeatures(cmd.Context(), cmd,
			true,  // noSAST
			true,  // noSCA
			true,  // noLicenses
			false, // noSecrets
			true,  // noContainers
			true,  // noIAC
		)
	},
}

// containersCmd runs a scan with only container analysis enabled.
var containersCmd = &cobra.Command{
	Use:   "containers",
	Short: "Run only container file analysis",
	Long: `Run a scan with only container analysis enabled. Equivalent to:
  vulnetix scan --enable-containers --no-licenses --no-sast --no-sca --no-secrets --no-iac

Analyzes container files (Dockerfile, Containerfile) only, without analyzing
package dependencies, licenses, or other security issues.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initDisplayContext(cmd, display.ModeText)
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		pullCliRules("containers", map[string]any{"images": []string{}, "registries": []string{}})
		return runScanWithFeatures(cmd.Context(), cmd,
			true,  // noSAST
			true,  // noSCA
			true,  // noLicenses
			true,  // noSecrets
			false, // noContainers
			true,  // noIAC
		)
	},
}

// iacCmd runs a scan with only IaC analysis enabled.
var iacCmd = &cobra.Command{
	Use:   "iac",
	Short: "Run only Infrastructure as Code (IaC) analysis",
	Long: `Run a scan with only IaC analysis enabled. Equivalent to:
  vulnetix scan --evaluate-iac --no-licenses --no-sast --no-sca --no-containers --no-secrets

Analyzes Infrastructure as Code files (Terraform HCL, Nix) only, without
analyzing package dependencies, licenses, or other security issues.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initDisplayContext(cmd, display.ModeText)
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		pullCliRules("iac", map[string]any{"frameworks": []string{}})
		return runScanWithFeatures(cmd.Context(), cmd,
			true,  // noSAST
			true,  // noSCA
			true,  // noLicenses
			true,  // noSecrets
			true,  // noContainers
			false, // noIAC
		)
	},
}

func init() {
	// scaCmd has no rule-pack support (pure dependency scanning).
	addScanFlags(scaCmd)
	rootCmd.AddCommand(scaCmd)

	// secrets, containers, iac, sast all accept external Rego rule packs
	// via --rule (along with --disable-default-rules, --list-default-rules, etc.)
	for _, cmd := range []*cobra.Command{secretsCmd, containersCmd, iacCmd, sastCmd} {
		addScanFlags(cmd)
		addSASTFlags(cmd)
		rootCmd.AddCommand(cmd)
	}
}

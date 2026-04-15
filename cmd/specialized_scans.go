package cmd

import (
	"github.com/spf13/cobra"
)

// scaCmd runs a scan with only SCA enabled.
var scaCmd = &cobra.Command{
	Use:   "sca",
	Short: "Run only Software Composition Analysis (SCA) scan",
	Long: `Run a scan with only SCA enabled. Equivalent to:
  vulnetix scan --evaluate-sca --no-licenses --no-sast --no-containers --no-secrets --no-iac

Performs vulnerability analysis on package dependencies only, without running
SAST, license analysis, secret detection, container analysis, or IaC analysis.`,
	RunE: func(cmd *cobra.Command, args []string) error {
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
	RunE: func(cmd *cobra.Command, args []string) error {
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
	RunE: func(cmd *cobra.Command, args []string) error {
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
	RunE: func(cmd *cobra.Command, args []string) error {
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
	RunE: func(cmd *cobra.Command, args []string) error {
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
	for _, cmd := range []*cobra.Command{scaCmd, secretsCmd, containersCmd, iacCmd} {
		addScanFlags(cmd)
		rootCmd.AddCommand(cmd)
	}
	// sast also gets SAST-specific flags (--rule, --disable-default-rules, etc.)
	addScanFlags(sastCmd)
	addSASTFlags(sastCmd)
	rootCmd.AddCommand(sastCmd)
}

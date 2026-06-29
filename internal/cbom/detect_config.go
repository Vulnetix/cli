package cbom

import (
	"path/filepath"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/sast"
)

const (
	// Crypto configuration lives in small files. Large structured files
	// (.json/.yaml test fixtures, API/SARIF dumps, lockfiles) are data, not
	// config — scanning them for algorithm names is slow and produces false
	// positives, so they are skipped above these caps. True config file types
	// get a more generous cap than generic structured data.
	maxCryptoConfigBytes = 512 * 1024
	maxDataConfigBytes   = 64 * 1024
)

// cryptoConfigExts are file types that are genuinely cryptographic / service
// configuration (TLS, SSH, OpenSSL, IPsec, IaC).
var cryptoConfigExts = map[string]bool{
	".conf": true, ".cnf": true, ".cfg": true, ".ini": true,
	".toml": true, ".properties": true, ".tf": true, ".tfvars": true,
}

// structuredExts are generic structured-data types that may carry config (k8s
// TLS policy, JWT alg) but are also commonly large data dumps.
var structuredExts = map[string]bool{
	".json": true, ".yaml": true, ".yml": true, ".xml": true,
}

var configNames = map[string]bool{
	"nginx.conf": true, "ssh_config": true, "sshd_config": true,
	"httpd.conf": true, "openssl.cnf": true, "haproxy.cfg": true,
}

// configBudget returns the max bytes scanned for a path, or 0 if the file is not
// a configuration file at all.
func configBudget(path string) int {
	base := strings.ToLower(filepath.Base(path))
	if configNames[base] {
		return maxCryptoConfigBytes
	}
	ext := strings.ToLower(filepath.Ext(path))
	if cryptoConfigExts[ext] {
		return maxCryptoConfigBytes
	}
	if structuredExts[ext] {
		return maxDataConfigBytes
	}
	return 0
}

// detectConfig scans configuration files for algorithm references via each
// algorithm's config_patterns, and resolves language-agnostic call_extractor
// tokens (e.g. a JWT "alg"). Large structured-data files are skipped (see
// configBudget) so vulnerability/test data dumps neither slow the scan nor
// register as crypto usage.
func (c *collector) detectConfig(input *sast.ScanInput) {
	if input == nil {
		return
	}
	for path, content := range input.FileContents {
		budget := configBudget(path)
		if budget == 0 || len(content) > budget {
			continue
		}
		for i := range c.cat.Algorithms {
			a := &c.cat.Algorithms[i]
			for _, re := range a.Config {
				for _, m := range matchLines(content, re) {
					c.addAlgo(a, cdx.CryptoEvidence{
						Method: "config", Category: "config", Locator: locOf(path, m.line), Snippet: m.text,
					}, "", "", "")
				}
			}
		}
		for i := range c.cat.Extractors {
			ex := &c.cat.Extractors[i]
			// Only the language-agnostic extractors (e.g. JWT alg) apply to config
			// files, which carry no programming-language signal.
			if ex.Languages != nil {
				continue
			}
			for _, sm := range findCaptures(content, ex.Re) {
				c.applyExtractor(ex.Role, sm.value, path, sm.line)
			}
		}
	}
}

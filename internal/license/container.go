package license

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
)

// FetchContainerLicense attempts to resolve a license for a container image or
// infrastructure-as-code package. Tries local tools first, then registry APIs.
//
// Handles:
//   - Docker/OCI images (podman/docker inspect → labels/annotations → registry)
//   - Terraform providers (registry API → GitHub source repo)
//   - Nix flakes (nix CLI if available)
func FetchContainerLicense(name, version, ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "docker":
		return resolveDockerLicense(name, version)
	case "terraform":
		return resolveTerraformLicense(name)
	case "nix":
		return resolveNixLicense(name)
	default:
		return ""
	}
}

// ── Docker / OCI images ──────────────────────────────────────────────────

func resolveDockerLicense(name, version string) string {
	ref := name
	if version != "" {
		ref = name + ":" + version
	}

	// 1. Check local image labels/annotations via podman or docker.
	if lic := inspectLocalImage(ref); lic != "" {
		return lic
	}

	// 2. Well-known official images.
	if lic := wellKnownDockerLicense(name); lic != "" {
		return lic
	}

	// 3. Try to extract source repo from annotations and resolve via GitHub.
	if source := inspectImageSource(ref); source != "" {
		if lic := resolveSourceRepoLicense(source); lic != "" {
			return lic
		}
	}

	// 4. Docker Hub API — check description for license references.
	if lic := dockerHubLicense(name); lic != "" {
		return lic
	}

	return ""
}

// inspectLocalImage checks OCI labels for license info via podman or docker.
func inspectLocalImage(ref string) string {
	for _, tool := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		cmd := exec.Command(tool, "inspect", ref)
		out, err := cmd.Output()
		if err != nil {
			continue
		}

		var images []struct {
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
			Annotations map[string]string `json:"Annotations"`
		}
		if err := json.Unmarshal(out, &images); err != nil || len(images) == 0 {
			continue
		}

		// Check all labels and annotations for license fields.
		for _, src := range []map[string]string{images[0].Config.Labels, images[0].Annotations} {
			for _, key := range []string{
				"org.opencontainers.image.licenses",
				"org.label-schema.license",
				"license",
				"License",
			} {
				if v, ok := src[key]; ok && v != "" {
					return NormalizeSPDX(v)
				}
			}
		}
	}
	return ""
}

// inspectImageSource extracts org.opencontainers.image.source from a local image.
func inspectImageSource(ref string) string {
	for _, tool := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		cmd := exec.Command(tool, "inspect", ref, "--format",
			`{{index .Annotations "org.opencontainers.image.source"}}`)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		source := strings.TrimSpace(string(out))
		if source != "" && source != "<no value>" {
			return source
		}
	}
	return ""
}

// resolveSourceRepoLicense extracts owner/repo from a GitHub URL and resolves license.
func resolveSourceRepoLicense(source string) string {
	// Parse GitHub URL: https://github.com/owner/repo.git#hash:path
	source = strings.TrimSuffix(source, "/")
	// Remove fragment (#hash:path).
	if idx := strings.Index(source, "#"); idx >= 0 {
		source = source[:idx]
	}
	// Remove .git suffix.
	source = strings.TrimSuffix(source, ".git")

	// Extract owner/repo.
	for _, prefix := range []string{"https://github.com/", "http://github.com/"} {
		if strings.HasPrefix(source, prefix) {
			path := strings.TrimPrefix(source, prefix)
			parts := strings.SplitN(path, "/", 3)
			if len(parts) >= 2 {
				return resolveRepoLicense(parts[0], parts[1])
			}
		}
	}
	return ""
}

// wellKnownDockerLicense returns licenses for official Docker Library images.
// These are curated from each project's upstream license.
var wellKnownDockerImages = map[string]string{
	// OS base images
	"alpine":       "MIT",
	"debian":       "MIT",        // Debian packaging is MIT; packages have own licenses
	"ubuntu":       "MIT",        // Canonical IP Policy
	"centos":       "GPL-2.0-only",
	"rockylinux":   "BSD-3-Clause",
	"almalinux":    "GPL-2.0-only",
	"fedora":       "MIT",
	"archlinux":    "GPL-2.0-only",
	"busybox":      "GPL-2.0-only",
	"clearlinux":   "Apache-2.0",
	"oraclelinux":  "GPL-2.0-only",
	"amazonlinux":  "Apache-2.0",
	"scratch":      "CC0-1.0", // empty image, no license constraints

	// Language runtimes
	"golang":       "BSD-3-Clause",
	"node":         "MIT",
	"python":       "PSF-2.0",
	"ruby":         "BSD-2-Clause",
	"rust":         "Apache-2.0",
	"openjdk":      "GPL-2.0-only",
	"eclipse-temurin": "GPL-2.0-only",
	"php":          "PHP-3.01",
	"perl":         "Artistic-2.0",
	"elixir":       "Apache-2.0",
	"erlang":       "Apache-2.0",
	"swift":        "Apache-2.0",
	"dotnet/sdk":   "MIT",
	"dotnet/runtime": "MIT",
	"dotnet/aspnet":  "MIT",
	"julia":        "MIT",
	"haskell":      "BSD-3-Clause",
	"clojure":      "EPL-1.0",
	"dart":         "BSD-3-Clause",

	// Databases
	"postgres":     "PostgreSQL",
	"mysql":        "GPL-2.0-only",
	"mariadb":      "GPL-2.0-only",
	"mongo":        "SSPL-1.0",
	"redis":        "BSD-3-Clause",
	"memcached":    "BSD-3-Clause",
	"cassandra":    "Apache-2.0",
	"couchdb":      "Apache-2.0",
	"elasticsearch": "SSPL-1.0",
	"influxdb":     "MIT",

	// Web servers / proxies
	"nginx":        "BSD-2-Clause",
	"httpd":        "Apache-2.0",
	"traefik":      "MIT",
	"caddy":        "Apache-2.0",
	"haproxy":      "GPL-2.0-only",
	"envoyproxy/envoy": "Apache-2.0",

	// Infrastructure
	"registry":     "Apache-2.0",
	"vault":        "BUSL-1.1",
	"consul":       "BUSL-1.1",
	"rabbitmq":     "MPL-2.0",
	"zookeeper":    "Apache-2.0",
	"nats":         "Apache-2.0",
	"etcd":         "Apache-2.0",
	"grafana/grafana": "AGPL-3.0-only",
	"prom/prometheus": "Apache-2.0",
	"jenkins/jenkins": "MIT",
	"sonarqube":    "LGPL-3.0-only",
	"gitlab/gitlab-ce": "MIT",
	"gitea/gitea":  "MIT",
}

func wellKnownDockerLicense(name string) string {
	if lic, ok := wellKnownDockerImages[name]; ok {
		return lic
	}
	// Try without registry prefix (e.g., "library/alpine" → "alpine").
	if strings.HasPrefix(name, "library/") {
		if lic, ok := wellKnownDockerImages[strings.TrimPrefix(name, "library/")]; ok {
			return lic
		}
	}
	return ""
}

// dockerHubLicense queries Docker Hub API for license hints in the repo description.
func dockerHubLicense(name string) string {
	// Docker Hub API for official "library" images.
	apiName := name
	if !strings.Contains(name, "/") {
		apiName = "library/" + name
	}
	u := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/", apiName)
	resp, err := getHTTPClient().Get(u)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var data struct {
		FullDescription string `json:"full_description"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	// Search for SPDX-like license references in the description.
	return extractLicenseFromDescription(data.FullDescription)
}

// extractLicenseFromDescription looks for license patterns in Docker Hub descriptions.
func extractLicenseFromDescription(desc string) string {
	// Docker Hub official images often have a "License" section.
	upper := strings.ToUpper(desc)

	// Look for common patterns like "licensed under the MIT License".
	patterns := []struct {
		contains string
		license  string
	}{
		{"LICENSED UNDER THE MIT", "MIT"},
		{"MIT LICENSE", "MIT"},
		{"APACHE LICENSE, VERSION 2.0", "Apache-2.0"},
		{"APACHE LICENSE 2.0", "Apache-2.0"},
		{"APACHE-2.0", "Apache-2.0"},
		{"BSD 3-CLAUSE", "BSD-3-Clause"},
		{"BSD 2-CLAUSE", "BSD-2-Clause"},
		{"GPL-2.0", "GPL-2.0-only"},
		{"GPL-3.0", "GPL-3.0-only"},
		{"MPL-2.0", "MPL-2.0"},
		{"LGPL-3.0", "LGPL-3.0-only"},
	}
	for _, p := range patterns {
		if strings.Contains(upper, p.contains) {
			return p.license
		}
	}
	return ""
}

// ── Terraform providers ──────────────────────────────────────────────────

func resolveTerraformLicense(name string) string {
	// 1. Query Terraform Registry for source repo.
	parts := strings.SplitN(name, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	namespace, provider := parts[0], parts[1]

	u := fmt.Sprintf("https://registry.terraform.io/v1/providers/%s/%s", namespace, provider)
	resp, err := getHTTPClient().Get(u)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		// Fallback: try GitHub with terraform-provider- prefix.
		return resolveRepoLicense(namespace, "terraform-provider-"+provider)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var data struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(body, &data); err != nil || data.Source == "" {
		// Fallback: guess GitHub repo name.
		return resolveRepoLicense(namespace, "terraform-provider-"+provider)
	}

	// Parse source URL → GitHub owner/repo.
	if lic := resolveSourceRepoLicense(data.Source); lic != "" {
		return lic
	}

	return ""
}

// ── Nix packages ─────────────────────────────────────────────────────────

func resolveNixLicense(name string) string {
	// Try nix CLI if available.
	if _, err := exec.LookPath("nix"); err == nil {
		// nix eval can query package metadata.
		cmd := exec.Command("nix", "eval", "--raw", fmt.Sprintf("nixpkgs#%s.meta.license.spdxId", name))
		cmd.Stderr = io.Discard
		out, err := cmd.Output()
		if err == nil {
			lic := strings.TrimSpace(string(out))
			if lic != "" {
				return NormalizeSPDX(lic)
			}
		}
	}

	// Well-known Nix ecosystem packages.
	switch name {
	case "nixpkgs":
		return "MIT"
	case "flake-utils":
		return "MIT"
	case "home-manager":
		return "MIT"
	case "nix-darwin":
		return "MIT"
	case "flake-compat":
		return "MIT"
	}

	return ""
}

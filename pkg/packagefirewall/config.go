package packagefirewall

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

type ConfigOptions struct {
	HomeDir  string
	ProxyURL string
	OrgID    string
	APIKey   string
}

type ConfigFile struct {
	Path       string
	Content    string
	Structured bool
}

func ConfigFiles(eco Ecosystem, opts ConfigOptions) ([]ConfigFile, error) {
	if err := RequireWriter(eco); err != nil {
		return nil, err
	}
	home := opts.HomeDir
	if home == "" {
		return nil, fmt.Errorf("home directory is required")
	}
	switch eco.ID {
	case "npm":
		return []ConfigFile{{Path: filepath.Join(home, ".npmrc"), Content: npmConfig(eco, opts)}}, nil
	case "pypi":
		return []ConfigFile{{Path: filepath.Join(home, ".config", "pip", "pip.conf"), Content: pypiConfig(eco, opts)}}, nil
	case "cargo":
		return []ConfigFile{
			{Path: filepath.Join(home, ".cargo", "config.toml"), Content: cargoConfig(eco, opts)},
			{Path: filepath.Join(home, ".cargo", "credentials.toml"), Content: cargoCredentials(eco, opts)},
		}, nil
	case "gem":
		return []ConfigFile{{Path: filepath.Join(home, ".gemrc"), Content: gemConfig(eco, opts)}}, nil
	case "hex":
		return []ConfigFile{{Path: filepath.Join(home, ".config", "vulnetix", "package-firewall", "hex.env"), Content: hexConfig(eco, opts)}}, nil
	case "pub":
		return []ConfigFile{{Path: filepath.Join(home, ".config", "vulnetix", "package-firewall", "pub.env"), Content: pubConfig(eco, opts)}}, nil
	case "maven":
		return []ConfigFile{{Path: filepath.Join(home, ".m2", "settings.xml"), Content: mavenConfig(eco, opts), Structured: true}}, nil
	case "nuget":
		return []ConfigFile{{Path: filepath.Join(home, ".nuget", "NuGet", "NuGet.Config"), Content: nugetConfig(eco, opts), Structured: true}}, nil
	case "composer":
		return []ConfigFile{{Path: filepath.Join(home, ".composer", "config.json"), Content: composerConfig(eco, opts), Structured: true}}, nil
	case "conan":
		return []ConfigFile{
			{Path: filepath.Join(home, ".conan2", "remotes.json"), Content: conanRemotesConfig(eco, opts), Structured: true},
			{Path: filepath.Join(home, ".conan2", "credentials.json"), Content: conanCredentialsConfig(opts), Structured: true},
		}, nil
	case "cran":
		return []ConfigFile{{Path: filepath.Join(home, ".Rprofile"), Content: cranConfig(eco, opts)}}, nil
	case "helm":
		return []ConfigFile{{Path: filepath.Join(home, ".config", "helm", "repositories.yaml"), Content: helmConfig(eco, opts), Structured: true}}, nil
	default:
		return nil, fmt.Errorf("automatic %s configuration is not implemented yet", eco.DisplayName)
	}
}

func npmConfig(eco Ecosystem, opts ConfigOptions) string {
	proxy := ProxyURLWithSlash(opts.ProxyURL, eco)
	u, _ := url.Parse(proxy)
	hostPath := strings.TrimPrefix(u.Host+u.Path, "/")
	password := base64.StdEncoding.EncodeToString([]byte(opts.APIKey))
	return strings.Join([]string{
		"registry=" + proxy,
		"//" + hostPath + ":username=" + opts.OrgID,
		"//" + hostPath + ":_password=" + password,
		"//" + hostPath + ":always-auth=true",
		"",
	}, "\n")
}

func pypiConfig(eco Ecosystem, opts ConfigOptions) string {
	return strings.Join([]string{
		"[global]",
		"index-url = " + withBasicAuth(ProxyURLWithSlash(opts.ProxyURL, eco)+"simple/", opts.OrgID, opts.APIKey),
		"",
	}, "\n")
}

func cargoConfig(eco Ecosystem, opts ConfigOptions) string {
	proxy := "sparse+" + ProxyURLWithSlash(opts.ProxyURL, eco)
	return strings.Join([]string{
		"[source.crates-io]",
		`replace-with = "vulnetix"`,
		"",
		"[source.vulnetix]",
		`registry = "` + proxy + `"`,
		"",
		"[registries.vulnetix]",
		`index = "` + proxy + `"`,
		`credential-provider = ["cargo:token"]`,
		"",
	}, "\n")
}

// cargoCredentials writes the Basic auth token cargo sends verbatim in the
// Authorization header to the sparse registry (cargo does not read netrc).
func cargoCredentials(_ Ecosystem, opts ConfigOptions) string {
	token := "Basic " + base64.StdEncoding.EncodeToString([]byte(opts.OrgID+":"+opts.APIKey))
	return strings.Join([]string{
		"[registries.vulnetix]",
		`token = "` + token + `"`,
		"",
	}, "\n")
}

// gemConfig embeds the credentials in the source URL; RubyGems/Bundler do not
// read netrc, so userinfo in the source is the portable way to authenticate.
func gemConfig(eco Ecosystem, opts ConfigOptions) string {
	src := withBasicAuth(ProxyURLWithSlash(opts.ProxyURL, eco), opts.OrgID, opts.APIKey)
	return strings.Join([]string{
		":sources:",
		"- " + src,
		"",
	}, "\n")
}

func hexConfig(eco Ecosystem, opts ConfigOptions) string {
	return strings.Join([]string{
		`export HEX_MIRROR="` + ProxyURL(opts.ProxyURL, eco) + `"`,
		"",
	}, "\n")
}

func pubConfig(eco Ecosystem, opts ConfigOptions) string {
	return strings.Join([]string{
		`export PUB_HOSTED_URL="` + ProxyURL(opts.ProxyURL, eco) + `"`,
		"",
	}, "\n")
}

func mavenConfig(eco Ecosystem, opts ConfigOptions) string {
	type server struct {
		ID       string `xml:"id"`
		Username string `xml:"username"`
		Password string `xml:"password"`
	}
	type mirror struct {
		ID       string `xml:"id"`
		MirrorOf string `xml:"mirrorOf"`
		URL      string `xml:"url"`
	}
	type settings struct {
		XMLName xml.Name `xml:"settings"`
		Servers []server `xml:"servers>server"`
		Mirrors []mirror `xml:"mirrors>mirror"`
	}
	out, _ := xml.MarshalIndent(settings{
		Servers: []server{{ID: "vulnetix-package-firewall", Username: opts.OrgID, Password: opts.APIKey}},
		Mirrors: []mirror{{ID: "vulnetix-package-firewall", MirrorOf: "*", URL: ProxyURLWithSlash(opts.ProxyURL, eco)}},
	}, "", "  ")
	return xml.Header + string(out) + "\n"
}

func nugetConfig(eco Ecosystem, opts ConfigOptions) string {
	return strings.Join([]string{
		`<?xml version="1.0" encoding="utf-8"?>`,
		`<configuration>`,
		`  <packageSources>`,
		`    <clear />`,
		`    <add key="vulnetix" value="` + ProxyURLWithSlash(opts.ProxyURL, eco) + `v3/index.json" />`,
		`  </packageSources>`,
		`  <packageSourceCredentials>`,
		`    <vulnetix>`,
		`      <add key="Username" value="` + xmlEscape(opts.OrgID) + `" />`,
		`      <add key="ClearTextPassword" value="` + xmlEscape(opts.APIKey) + `" />`,
		`    </vulnetix>`,
		`  </packageSourceCredentials>`,
		`</configuration>`,
		"",
	}, "\n")
}

func composerConfig(eco Ecosystem, opts ConfigOptions) string {
	cfg := map[string]any{
		"repositories": map[string]any{
			"vulnetix": map[string]string{
				"type": "composer",
				"url":  ProxyURL(opts.ProxyURL, eco),
			},
			"packagist.org": false,
		},
		"http-basic": map[string]map[string]string{
			proxyHost(opts.ProxyURL): {
				"username": opts.OrgID,
				"password": opts.APIKey,
			},
		},
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return string(out) + "\n"
}

func conanRemotesConfig(eco Ecosystem, opts ConfigOptions) string {
	cfg := map[string]any{
		"remotes": []map[string]any{
			{
				"name":       "vulnetix",
				"url":        ProxyURL(opts.ProxyURL, eco),
				"verify_ssl": true,
			},
			{
				"name":       "conancenter",
				"url":        "https://center2.conan.io",
				"verify_ssl": true,
				"disabled":   true,
			},
		},
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return string(out) + "\n"
}

func conanCredentialsConfig(opts ConfigOptions) string {
	cfg := map[string]any{
		"credentials": []map[string]string{
			{
				"remote":   "vulnetix",
				"user":     opts.OrgID,
				"password": opts.APIKey,
			},
		},
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return string(out) + "\n"
}

func cranConfig(eco Ecosystem, opts ConfigOptions) string {
	return strings.Join([]string{
		`options(repos = c(CRAN = "` + ProxyURL(opts.ProxyURL, eco) + `"))`,
		`options(download.file.method = "libcurl")`,
		"",
	}, "\n")
}

func helmConfig(eco Ecosystem, opts ConfigOptions) string {
	return strings.Join([]string{
		"apiVersion: v1",
		"generated: \"0001-01-01T00:00:00Z\"",
		"repositories:",
		"- name: vulnetix",
		"  url: " + yamlString(ProxyURL(opts.ProxyURL, eco)),
		"  username: " + yamlString(opts.OrgID),
		"  password: " + yamlString(opts.APIKey),
		"  pass_credentials_all: true",
		"",
	}, "\n")
}

func yamlString(s string) string {
	return strconv.Quote(s)
}

func withBasicAuth(rawURL, username, password string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = url.UserPassword(username, password)
	return u.String()
}

func proxyHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "packages.vulnetix.com"
	}
	return u.Host
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

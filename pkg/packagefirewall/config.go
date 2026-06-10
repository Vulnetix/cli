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
		// .npmrc covers npm, pnpm, bun, and Yarn Classic (v1). Yarn Berry (v2+)
		// ignores .npmrc and needs its own .yarnrc.yml.
		return []ConfigFile{
			{Path: filepath.Join(home, ".npmrc"), Content: npmConfig(eco, opts)},
			{Path: filepath.Join(home, ".yarnrc.yml"), Content: yarnBerryConfig(eco, opts)},
		}, nil
	case "pypi":
		// pip.conf covers pip, pipenv, and Poetry's legacy resolver. uv ignores
		// pip.conf and needs its own uv.toml.
		return []ConfigFile{
			{Path: filepath.Join(home, ".config", "pip", "pip.conf"), Content: pypiConfig(eco, opts)},
			{Path: filepath.Join(home, ".config", "uv", "uv.toml"), Content: uvConfig(eco, opts)},
		}, nil
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
		// Dart pub rejects userinfo in PUB_HOSTED_URL and authenticates only via a
		// bearer token in pub-tokens.json; the firewall accepts that token (it is
		// base64("org:key"), the same secret as Basic).
		return []ConfigFile{
			{Path: filepath.Join(home, ".config", "vulnetix", "package-firewall", "pub.env"), Content: pubConfig(eco, opts)},
			{Path: filepath.Join(home, ".config", "dart", "pub-tokens.json"), Content: pubTokensConfig(eco, opts), Structured: true},
		}, nil
	case "maven":
		return []ConfigFile{{Path: filepath.Join(home, ".m2", "settings.xml"), Content: mavenConfig(eco, opts), Structured: true}}, nil
	case "nuget":
		return []ConfigFile{{Path: filepath.Join(home, ".nuget", "NuGet", "NuGet.Config"), Content: nugetConfig(eco, opts), Structured: true}}, nil
	case "composer":
		// Composer reads repository config from config.json but credentials only
		// from auth.json (top-level http-basic) — not from config.json's top level.
		return []ConfigFile{
			{Path: filepath.Join(home, ".composer", "config.json"), Content: composerConfig(eco, opts), Structured: true},
			{Path: filepath.Join(home, ".composer", "auth.json"), Content: composerAuthConfig(opts), Structured: true},
		}, nil
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
	auth := base64.StdEncoding.EncodeToString([]byte(opts.OrgID + ":" + opts.APIKey))
	return strings.Join([]string{
		"registry=" + proxy,
		"//" + hostPath + ":_auth=" + auth,
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

// yarnBerryConfig configures Yarn Berry (v2+), which ignores .npmrc. It pins the
// default registry to the firewall and scopes Basic auth to the firewall host.
// npmAuthIdent is the plaintext "user:password" pair; Yarn base64-encodes it when
// it contains a colon (an org UUID never does).
func yarnBerryConfig(eco Ecosystem, opts ConfigOptions) string {
	proxy := ProxyURLWithSlash(opts.ProxyURL, eco)
	u, _ := url.Parse(proxy)
	scope := "//" + strings.TrimPrefix(u.Host+u.Path, "/")
	return strings.Join([]string{
		"npmRegistryServer: " + yamlString(proxy),
		"npmRegistries:",
		"  " + yamlString(scope) + ":",
		"    npmAlwaysAuth: true",
		"    npmAuthIdent: " + yamlString(opts.OrgID+":"+opts.APIKey),
		"",
	}, "\n")
}

// uvConfig configures uv, which ignores pip.conf. The credentials are embedded in
// the index URL userinfo (url.String percent-encodes them); default = true makes
// the firewall the sole index, with no implicit fallback to pypi.org.
func uvConfig(eco Ecosystem, opts ConfigOptions) string {
	index := withBasicAuth(ProxyURLWithSlash(opts.ProxyURL, eco)+"simple/", opts.OrgID, opts.APIKey)
	return strings.Join([]string{
		"[[index]]",
		`url = "` + index + `"`,
		"default = true",
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

// hexConfig embeds the credentials in HEX_MIRROR; Hex/mix has no separate auth
// file for a mirror, and the firewall requires auth on every request. Hex honors
// userinfo in the mirror URL.
func hexConfig(eco Ecosystem, opts ConfigOptions) string {
	mirror := withBasicAuth(ProxyURL(opts.ProxyURL, eco), opts.OrgID, opts.APIKey)
	return strings.Join([]string{
		`export HEX_MIRROR="` + mirror + `"`,
		"",
	}, "\n")
}

func pubConfig(eco Ecosystem, opts ConfigOptions) string {
	return strings.Join([]string{
		`export PUB_HOSTED_URL="` + ProxyURL(opts.ProxyURL, eco) + `"`,
		"",
	}, "\n")
}

// pubTokensConfig writes Dart's pub-tokens.json. pub cannot send Basic auth or
// userinfo, so it carries a per-host bearer token; the firewall accepts that
// token as base64("orgID:apiKey") — the same secret it accepts via Basic.
func pubTokensConfig(eco Ecosystem, opts ConfigOptions) string {
	token := base64.StdEncoding.EncodeToString([]byte(opts.OrgID + ":" + opts.APIKey))
	cfg := map[string]any{
		"version": 1,
		"hosted": []map[string]string{
			{"url": ProxyURL(opts.ProxyURL, eco), "token": token},
		},
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return string(out) + "\n"
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
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	return string(out) + "\n"
}

// composerAuthConfig writes ~/.composer/auth.json. Composer only reads HTTP Basic
// credentials from auth.json (or config.http-basic) — http-basic at the top level
// of config.json is ignored, which otherwise yields a 401 against the firewall.
func composerAuthConfig(opts ConfigOptions) string {
	cfg := map[string]any{
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

// cranConfig embeds the credentials in the repos URL. R/Bioconductor have no
// netrc-independent auth file; libcurl (the configured downloader) honors
// userinfo in the URL, and the firewall requires auth on every request.
func cranConfig(eco Ecosystem, opts ConfigOptions) string {
	repo := withBasicAuth(ProxyURL(opts.ProxyURL, eco), opts.OrgID, opts.APIKey)
	return strings.Join([]string{
		`options(repos = c(CRAN = "` + repo + `"))`,
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

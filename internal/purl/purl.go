package purl

import (
	"fmt"
	"net/url"
	"strings"
)

// PackageURL represents a parsed Package URL (PURL) per the spec.
type PackageURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

// Parse parses a PURL string into a PackageURL struct.
func Parse(raw string) (*PackageURL, error) {
	if raw == "" {
		return nil, fmt.Errorf("empty PURL string")
	}

	// 1. Validate and strip scheme
	if !strings.HasPrefix(raw, "pkg:") {
		return nil, fmt.Errorf("invalid PURL: missing 'pkg:' scheme")
	}
	remainder := raw[4:]

	// 2. Strip subpath (after #)
	var subpath string
	if idx := strings.Index(remainder, "#"); idx != -1 {
		subpath, _ = url.PathUnescape(remainder[idx+1:])
		remainder = remainder[:idx]
	}

	// 3. Strip qualifiers (after ?)
	qualifiers := make(map[string]string)
	if idx := strings.Index(remainder, "?"); idx != -1 {
		qStr := remainder[idx+1:]
		remainder = remainder[:idx]
		for _, pair := range strings.Split(qStr, "&") {
			if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
				k, _ := url.PathUnescape(kv[0])
				v, _ := url.PathUnescape(kv[1])
				qualifiers[k] = v
			}
		}
	}

	// 4. Strip version (after last @)
	var version string
	if idx := strings.LastIndex(remainder, "@"); idx != -1 {
		version, _ = url.PathUnescape(remainder[idx+1:])
		remainder = remainder[:idx]
	}

	// 5. Split type from remainder (first /)
	slashIdx := strings.Index(remainder, "/")
	if slashIdx == -1 {
		return nil, fmt.Errorf("invalid PURL: missing type or name")
	}
	purlType := strings.ToLower(remainder[:slashIdx])
	remainder = remainder[slashIdx+1:]

	if purlType == "" {
		return nil, fmt.Errorf("invalid PURL: empty type")
	}

	// 6. Split namespace and name (last /)
	var namespace, name string
	if lastSlash := strings.LastIndex(remainder, "/"); lastSlash != -1 {
		namespace, _ = url.PathUnescape(remainder[:lastSlash])
		name, _ = url.PathUnescape(remainder[lastSlash+1:])
	} else {
		name, _ = url.PathUnescape(remainder)
	}

	if name == "" {
		return nil, fmt.Errorf("invalid PURL: empty name")
	}

	return &PackageURL{
		Type:       purlType,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
		Subpath:    subpath,
	}, nil
}

// PackageName returns the type-specific package name suitable for VDB API queries.
func (p *PackageURL) PackageName() string {
	switch p.Type {
	case "npm":
		if p.Namespace != "" {
			return "@" + p.Namespace + "/" + p.Name
		}
		return p.Name
	case "maven":
		if p.Namespace != "" {
			return p.Namespace + ":" + p.Name
		}
		return p.Name
	case "golang":
		if p.Namespace != "" {
			return p.Namespace + "/" + p.Name
		}
		return p.Name
	default:
		return p.Name
	}
}

// String returns the canonical PURL string representation.
func (p *PackageURL) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteString("/")
	if p.Namespace != "" {
		b.WriteString(url.PathEscape(p.Namespace))
		b.WriteString("/")
	}
	b.WriteString(url.PathEscape(p.Name))
	if p.Version != "" {
		b.WriteString("@")
		b.WriteString(url.PathEscape(p.Version))
	}
	if len(p.Qualifiers) > 0 {
		b.WriteString("?")
		first := true
		for k, v := range p.Qualifiers {
			if !first {
				b.WriteString("&")
			}
			b.WriteString(url.PathEscape(k))
			b.WriteString("=")
			b.WriteString(url.PathEscape(v))
			first = false
		}
	}
	if p.Subpath != "" {
		b.WriteString("#")
		b.WriteString(url.PathEscape(p.Subpath))
	}
	return b.String()
}

var ecosystemMap = map[string]string{
	"npm":              "npm",
	"maven":            "Maven",
	"pypi":             "PyPI",
	"golang":           "Go",
	"cargo":            "crates.io",
	"nuget":            "NuGet",
	"gem":              "RubyGems",
	"composer":         "Packagist",
	"swift":            "SwiftURL",
	"cocoapods":        "CocoaPods",
	"pub":              "Pub",
	"hex":              "Hex",
	"conda":            "Conda",
	"conan":            "Conan",
	"huggingface":      "HuggingFace",
	"mlflow":           "MLflow",
	"julia":            "Julia",
	"luarocks":         "LuaRocks",
	"opam":             "opam",
	"cpan":             "CPAN",
	"hackage":          "Hackage",
	"cran":             "CRAN",
	"yocto":            "Yocto",
	"bitnami":          "Bitnami",
	"bazel":            "Bazel",
	"qpkg":             "QPKG",
	"vscode-extension": "VSCode",
	"deb":              "Debian",
	"rpm":              "RPM",
	"apk":              "Alpine",
	"alpm":             "Arch Linux",
	"docker":           "Docker",
	"oci":              "OCI",
	"github":           "GitHub",
	"bitbucket":        "Bitbucket",
	"generic":          "Generic",
}

// EcosystemForType maps a PURL type to the VDB ecosystem name.
func EcosystemForType(purlType string) (string, bool) {
	eco, ok := ecosystemMap[strings.ToLower(purlType)]
	return eco, ok
}

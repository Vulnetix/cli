package binpkg

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// maxJVMArchiveBytes bounds how much of a jar entry is read for metadata.
const maxJVMArchiveBytes = 1 << 20

// maxNestedJars bounds how many embedded jars are opened inside a fat jar. Spring
// Boot applications routinely carry a hundred; a runaway archive should not turn
// one SBOM component into an unbounded walk.
const maxNestedJars = 512

// FromJVMArchive recovers Maven coordinates from a jar/war/ear. The three
// evidence sources, in descending confidence:
//
//  1. META-INF/maven/<group>/<artifact>/pom.properties — written by Maven itself
//  2. META-INF/MANIFEST.MF Implementation-* / Bundle-SymbolicName attributes
//  3. the archive filename ("commons-lang3-3.14.0.jar")
//
// Fat jars are unpacked one level: every jar under BOOT-INF/lib, WEB-INF/lib or
// lib/ is inspected the same way, which is where a Spring Boot application's real
// dependency set lives.
func FromJVMArchive(path string) Result {
	res := Result{Attributes: map[string]string{}}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return Result{}
	}
	defer zr.Close()
	res.Format = "jvm"

	self, nested := scanJVMEntries(&zr.Reader, path, path)
	res.Packages = append(res.Packages, self...)
	if len(self) == 0 {
		if pkg, ok := packageFromArchiveName(path, path); ok {
			res.Packages = append(res.Packages, pkg)
		}
	}
	for i := range res.Packages {
		res.Packages[i].IsDirect = true
	}

	// Nested libraries: dependencies of the outer artefact, so not direct.
	var nestedKeys []string
	for _, entry := range nested {
		for _, pkg := range entry.packages {
			pkg.IsDirect = false
			res.Packages = append(res.Packages, pkg)
			nestedKeys = append(nestedKeys, pkg.Name+"@"+pkg.Version)
		}
		res.Errors = append(res.Errors, entry.errs...)
	}
	if len(res.Packages) > 0 && len(nestedKeys) > 0 {
		outer := res.Packages[0]
		res.Edges = append(res.Edges, Edge{From: outer.Name + "@" + outer.Version, DependsOn: nestedKeys})
	}
	if len(nested) > 0 {
		res.Attributes["jvm-nested-libraries"] = fmt.Sprintf("%d", len(nested))
	}
	if len(res.Attributes) == 0 {
		res.Attributes = nil
	}
	if len(res.Packages) == 0 {
		return Result{}
	}
	return res
}

type nestedArchive struct {
	packages []Package
	errs     []string
}

// scanJVMEntries reads coordinates for the archive itself and for every jar
// nested one level inside it. binaryPath is what gets recorded as the discovering
// artefact so a nested library still points at the file on disk.
func scanJVMEntries(zr *zip.Reader, archivePath, binaryPath string) ([]Package, []nestedArchive) {
	var own []Package
	var manifest []byte
	var nested []nestedArchive
	nestedCount := 0

	for _, f := range zr.File {
		name := filepath.ToSlash(f.Name)
		switch {
		case strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.properties"):
			data, err := readZipEntry(f)
			if err != nil {
				continue
			}
			if pkg, ok := packageFromPomProperties(data, archivePath, binaryPath); ok {
				own = append(own, pkg)
			}
		case name == "META-INF/MANIFEST.MF":
			if data, err := readZipEntry(f); err == nil {
				manifest = data
			}
		case isNestedLibrary(name):
			if nestedCount >= maxNestedJars {
				continue
			}
			nestedCount++
			nested = append(nested, readNestedJar(f, name, binaryPath))
		}
	}

	if len(own) == 0 && manifest != nil {
		if pkg, ok := packageFromManifest(manifest, archivePath, binaryPath); ok {
			own = append(own, pkg)
		}
	}
	return own, nested
}

func isNestedLibrary(name string) bool {
	if !strings.HasSuffix(strings.ToLower(name), ".jar") {
		return false
	}
	return strings.HasPrefix(name, "BOOT-INF/lib/") ||
		strings.HasPrefix(name, "WEB-INF/lib/") ||
		strings.HasPrefix(name, "lib/") ||
		strings.HasPrefix(name, "APP-INF/lib/")
}

func readNestedJar(f *zip.File, name, binaryPath string) nestedArchive {
	data, err := readZipEntry(f)
	if err != nil {
		return nestedArchive{errs: []string{fmt.Sprintf("%s!%s: %v", binaryPath, name, err)}}
	}
	inner, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nestedArchive{errs: []string{fmt.Sprintf("%s!%s: %v", binaryPath, name, err)}}
	}
	label := binaryPath + "!" + name
	pkgs, _ := scanJVMEntries(inner, label, binaryPath)
	if len(pkgs) == 0 {
		if pkg, ok := packageFromArchiveName(name, binaryPath); ok {
			pkgs = append(pkgs, pkg)
		}
	}
	for i := range pkgs {
		pkgs[i].Detail = "nested in " + filepath.Base(binaryPath) + ": " + name
	}
	return nestedArchive{packages: pkgs}
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, maxJVMArchiveBytes))
}

func packageFromPomProperties(data []byte, locator, binaryPath string) (Package, bool) {
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	group, artifact, version := fields["groupId"], fields["artifactId"], fields["version"]
	if group == "" || artifact == "" {
		return Package{}, false
	}
	return Package{
		Name: group + ":" + artifact, Version: version, Ecosystem: "maven", Scope: ScopeProduction,
		Method: MethodJVMArchive, Detail: "META-INF/maven pom.properties in " + filepath.Base(locator),
		Confidence: "high", BinaryPath: binaryPath,
	}, true
}

var manifestAttr = regexp.MustCompile(`(?m)^([A-Za-z0-9-]+)\s*:\s*(.*)$`)

func packageFromManifest(data []byte, locator, binaryPath string) (Package, bool) {
	attrs := map[string]string{}
	for _, m := range manifestAttr.FindAllStringSubmatch(string(data), -1) {
		attrs[strings.ToLower(m[1])] = strings.TrimSpace(m[2])
	}
	version := firstNonEmpty(attrs["implementation-version"], attrs["bundle-version"], attrs["specification-version"])
	group := firstNonEmpty(attrs["implementation-vendor-id"], attrs["automatic-module-name"], attrs["bundle-symbolicname"])
	artifact := firstNonEmpty(attrs["implementation-title"], attrs["bundle-name"], attrs["specification-title"])
	if artifact == "" && group == "" {
		return Package{}, false
	}
	name := artifact
	if group != "" && artifact != "" && !strings.Contains(artifact, ":") {
		name = group + ":" + artifact
	} else if artifact == "" {
		name = group
	}
	// Symbolic names carry OSGi directives after a semicolon.
	name = strings.TrimSpace(strings.SplitN(name, ";", 2)[0])
	if name == "" || version == "" {
		return Package{}, false
	}
	return Package{
		Name: name, Version: version, Ecosystem: "maven", Scope: ScopeProduction,
		Method: MethodJVMArchive, Detail: "MANIFEST.MF in " + filepath.Base(locator),
		Confidence: "medium", BinaryPath: binaryPath,
	}, true
}

var archiveNameVersion = regexp.MustCompile(`^(.+?)-(\d[0-9A-Za-z._+-]*)$`)

func packageFromArchiveName(path, binaryPath string) (Package, bool) {
	base := filepath.Base(path)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	m := archiveNameVersion.FindStringSubmatch(stem)
	if m == nil {
		return Package{}, false
	}
	return Package{
		Name: m[1], Version: m[2], Ecosystem: "maven", Scope: ScopeProduction,
		Method: MethodJVMArchive, Detail: "archive filename " + base,
		Confidence: "low", BinaryPath: binaryPath,
	}, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

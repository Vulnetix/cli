package scan

import (
	"github.com/Vulnetix/vdb-sca-match/parse"

	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pkgByName(pkgs []ScopedPackage, name string) (ScopedPackage, bool) {
	for _, p := range pkgs {
		if p.Name == name {
			return p, true
		}
	}
	return ScopedPackage{}, false
}

func TestParseKubernetesScoped(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      initContainers:
        - name: migrate
          image: ghcr.io/acme/migrate:2.0.0
      containers:
        - name: api
          image: ghcr.io/acme/api:1.2.3
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cron
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: docker.io/library/busybox:1.36
`
	pkgs, err := parse.ParseManifest([]byte(yaml), "kubernetes.yaml", "deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 images, got %d: %+v", len(pkgs), pkgs)
	}
	api, ok := pkgByName(pkgs, "ghcr.io/acme/api")
	if !ok || api.Version != "1.2.3" || api.Ecosystem != "oci" {
		t.Errorf("api image not parsed: %+v", api)
	}
	if api.RegistryType != "ghcr" || !api.IsPrivateRegistry {
		t.Errorf("ghcr registry enrichment wrong: type=%q private=%v", api.RegistryType, api.IsPrivateRegistry)
	}
	bb, _ := pkgByName(pkgs, "docker.io/library/busybox")
	if bb.RegistryType != "dockerhub" || bb.IsPrivateRegistry {
		t.Errorf("dockerhub classification wrong: %+v", bb)
	}
}

func TestParseHelmChartScoped(t *testing.T) {
	dir := t.TempDir()
	chart := filepath.Join(dir, "Chart.yaml")
	_ = os.WriteFile(chart, []byte(`
apiVersion: v2
name: myapp
version: 0.1.0
dependencies:
  - name: postgresql
    version: 12.1.2
    repository: https://charts.bitnami.com/bitnami
`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(`
image:
  repository: ghcr.io/acme/app
  tag: 3.4.5
sidecar:
  image: docker.io/library/redis:7
`), 0o644)
	pkgs, err := parse.ParseManifest([]byte(readFile(t, chart)), "Chart.yaml", chart)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := pkgByName(pkgs, "postgresql"); !ok || p.Ecosystem != "helm" || p.Version != "12.1.2" {
		t.Errorf("helm dep not parsed: %+v", p)
	}
	if p, ok := pkgByName(pkgs, "ghcr.io/acme/app"); !ok || p.Version != "3.4.5" || p.Ecosystem != "oci" {
		t.Errorf("values image (repo+tag) not parsed: %+v", p)
	}
	if _, ok := pkgByName(pkgs, "docker.io/library/redis"); !ok {
		t.Errorf("values shorthand image not parsed")
	}
}

func TestParseCondaEnvScoped(t *testing.T) {
	env := `
name: myenv
dependencies:
  - python=3.11
  - numpy>=1.24
  - conda-forge::scipy=1.10
  - pip:
      - requests==2.31.0
      - flask
`
	pkgs, _ := parse.ParseManifest([]byte(env), "environment.yml", "environment.yml")
	if p, ok := pkgByName(pkgs, "numpy"); !ok || p.Ecosystem != "conda" || p.Version != "1.24" {
		t.Errorf("conda numpy: %+v", p)
	}
	if p, ok := pkgByName(pkgs, "scipy"); !ok || p.Version != "1.10" {
		t.Errorf("channel-prefixed conda dep: %+v", p)
	}
	if p, ok := pkgByName(pkgs, "requests"); !ok || p.Ecosystem != "pypi" || p.Version != "2.31.0" {
		t.Errorf("nested pip dep should be pypi: %+v", p)
	}
}

func TestParseSetupPyAndCfg(t *testing.T) {
	py := `setup(
    name="x",
    install_requires=[
        "flask>=2.0",
        "boto3==1.34.0",
    ],
)`
	pkgs, _ := parse.ParseManifest([]byte(py), "setup.py", "setup.py")
	if p, ok := pkgByName(pkgs, "flask"); !ok || p.Ecosystem != "pypi" || p.Version != "2.0" {
		t.Errorf("setup.py flask: %+v", p)
	}
	cfg := `[options]
install_requires =
    django>=4.2
    requests
`
	cpkgs, _ := parse.ParseManifest([]byte(cfg), "setup.cfg", "setup.cfg")
	if p, ok := pkgByName(cpkgs, "django"); !ok || p.Version != "4.2" {
		t.Errorf("setup.cfg django: %+v", p)
	}
	if _, ok := pkgByName(cpkgs, "requests"); !ok {
		t.Errorf("setup.cfg requests missing")
	}
}

func TestParsePackagesConfig(t *testing.T) {
	xml := `<?xml version="1.0"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="Serilog" version="3.1.1" />
</packages>`
	pkgs, err := parse.ParseManifest([]byte(xml), "packages.config", "packages.config")
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := pkgByName(pkgs, "Newtonsoft.Json"); !ok || p.Ecosystem != "nuget" || p.Version != "13.0.3" {
		t.Errorf("packages.config: %+v", p)
	}
}

func TestParseClojureAndMill(t *testing.T) {
	lein := `(defproject my-app "0.1.0"
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [ring/ring-core "1.9.6"]])`
	lpkgs, _ := parse.ParseManifest([]byte(lein), "project.clj", "project.clj")
	if p, ok := pkgByName(lpkgs, "org.clojure:clojure"); !ok || p.Ecosystem != "clojars" || p.Version != "1.11.1" {
		t.Errorf("leiningen dep: %+v", p)
	}
	deps := `{:deps {org.clojure/clojure {:mvn/version "1.11.1"}
        cheshire/cheshire {:mvn/version "5.12.0"}}}`
	dpkgs, _ := parse.ParseManifest([]byte(deps), "deps.edn", "deps.edn")
	if p, ok := pkgByName(dpkgs, "cheshire:cheshire"); !ok || p.Version != "5.12.0" {
		t.Errorf("deps.edn dep: %+v", p)
	}
	mill := `def ivyDeps = Agg(ivy"com.lihaoyi::os-lib:0.9.1", ivy"org.slf4j:slf4j-api:2.0.7")`
	mpkgs, _ := parse.ParseManifest([]byte(mill), "build.sc", "build.sc")
	if p, ok := pkgByName(mpkgs, "com.lihaoyi:os-lib"); !ok || p.Ecosystem != "maven" || p.Version != "0.9.1" {
		t.Errorf("mill scala dep: %+v", p)
	}
	if _, ok := pkgByName(mpkgs, "org.slf4j:slf4j-api"); !ok {
		t.Errorf("mill java dep missing")
	}
}

func TestParseRegistryConfig(t *testing.T) {
	dir := t.TempDir()
	npmrc := filepath.Join(dir, ".npmrc")
	_ = os.WriteFile(npmrc, []byte(`registry=https://nexus.corp.example.com/repository/npm/
@acme:registry=https://npm.pkg.github.com
//nexus.corp.example.com/:_authToken=SECRETSHOULDNOTLEAK
`), 0o644)
	eps := ParseRegistryConfig(npmrc, "npm")
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %+v", len(eps), eps)
	}
	var privateFound bool
	for _, e := range eps {
		if e.URL == "https://nexus.corp.example.com/repository/npm/" && e.Private {
			privateFound = true
		}
		if strings.Contains(e.URL, "authToken") {
			t.Errorf("auth token must never be captured: %+v", e)
		}
	}
	if !privateFound {
		t.Errorf("private nexus registry not flagged")
	}
}

func TestDetectManifestNewTypes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	// Kubernetes content-sniff on a generically-named yaml.
	k8s := write("deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
	if info, ok := DetectManifest(k8s); !ok || info.Type != "kubernetes.yaml" || info.Language != "kubernetes" {
		t.Errorf("k8s detection: %+v ok=%v", info, ok)
	}
	// Chart.yaml exact-name → helm.
	chart := write("Chart.yaml", "apiVersion: v2\nname: x\nversion: 1.0.0\n")
	if info, ok := DetectManifest(chart); !ok || info.Ecosystem != "helm" {
		t.Errorf("helm Chart.yaml detection: %+v ok=%v", info, ok)
	}
	// environment.yml → conda (exact name wins over k8s/compose sniff).
	conda := write("environment.yml", "name: e\ndependencies:\n  - numpy\n")
	if info, ok := DetectManifest(conda); !ok || info.Ecosystem != "conda" {
		t.Errorf("conda detection: %+v ok=%v", info, ok)
	}
	// A plain docker-compose file must NOT be misread as kubernetes.
	compose := write("stack.yaml", "services:\n  web:\n    image: nginx:1.25\n")
	// stack.yaml is a Haskell manifest by exact name; use a different name.
	_ = compose
	compose2 := write("my-stack.yml", "services:\n  web:\n    image: nginx:1.25\n")
	if info, ok := DetectManifest(compose2); !ok || info.Type != "compose.yaml" {
		t.Errorf("compose still detected: %+v ok=%v", info, ok)
	}
	for _, name := range []string{"packages.config", "project.clj", "deps.edn", "setup.py", "npm-shrinkwrap.json", ".npmrc", "build.sc"} {
		p := write(name, "")
		if _, ok := DetectManifest(p); !ok {
			t.Errorf("%s not detected", name)
		}
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

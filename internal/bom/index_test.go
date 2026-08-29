package bom

import (
	"os"
	"path/filepath"
	"testing"
)

// corpusFixture writes a small multi-document corpus and returns its directory.
//
// Three services sharing dependencies at different versions, which is the shape
// every corpus question is about.
func corpusFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("payments.cdx.json", `{
	  "bomFormat":"CycloneDX","specVersion":"1.6","version":1,
	  "serialNumber":"urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	  "metadata":{
	    "timestamp":"2026-08-01T00:00:00Z",
	    "component":{"type":"application","bom-ref":"root","name":"payment-service","version":"2.4.0"},
	    "properties":[
	      {"name":"vulnetix:deployment/cluster","value":"prod-eu"},
	      {"name":"vulnetix:deployment/project","value":"payment-service"}
	    ]
	  },
	  "components":[
	    {"type":"library","bom-ref":"pkg:npm/lodash@4.17.20","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20","licenses":[{"license":{"id":"MIT"}}]},
	    {"type":"library","bom-ref":"pkg:npm/express@4.18.2","name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2"},
	    {"type":"library","bom-ref":"pkg:npm/left-pad@1.3.0","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}
	  ],
	  "dependencies":[
	    {"ref":"root","dependsOn":["pkg:npm/lodash@4.17.20","pkg:npm/express@4.18.2"]},
	    {"ref":"pkg:npm/express@4.18.2","dependsOn":["pkg:npm/left-pad@1.3.0"]}
	  ],
	  "vulnerabilities":[
	    {"id":"CVE-2021-44228","description":"Log4Shell remote code execution",
	     "ratings":[{"score":10.0,"severity":"critical"}],
	     "affects":[{"ref":"pkg:npm/lodash@4.17.20"}]}
	  ]
	}`)

	write("checkout.cdx.json", `{
	  "bomFormat":"CycloneDX","specVersion":"1.6","version":1,
	  "serialNumber":"urn:uuid:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	  "metadata":{
	    "timestamp":"2026-08-02T00:00:00Z",
	    "component":{"type":"application","bom-ref":"root","name":"checkout-service","version":"1.9.0"},
	    "properties":[{"name":"vulnetix:deployment/cluster","value":"prod-us"}]
	  },
	  "components":[
	    {"type":"library","bom-ref":"pkg:npm/lodash@4.17.21","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","licenses":[{"license":{"id":"MIT"}}]},
	    {"type":"library","bom-ref":"pkg:npm/chalk@5.3.0","name":"chalk","version":"5.3.0","purl":"pkg:npm/chalk@5.3.0","licenses":[{"license":{"id":"AGPL-3.0-only"}}]}
	  ],
	  "dependencies":[
	    {"ref":"root","dependsOn":["pkg:npm/lodash@4.17.21","pkg:npm/chalk@5.3.0"]}
	  ]
	}`)

	// SPDX, so the corpus proves it queries across formats.
	write("docs.spdx.json", `{
	  "spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
	  "name":"docs-site","documentNamespace":"https://example.com/spdx/docs",
	  "creationInfo":{"created":"2026-08-03T00:00:00Z","creators":["Tool: syft-1.18.1"]},
	  "documentDescribes":["SPDXRef-Package-root"],
	  "packages":[
	    {"SPDXID":"SPDXRef-Package-root","name":"docs-site","versionInfo":"3.0.0",
	     "downloadLocation":"NOASSERTION","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION",
	     "copyrightText":"NOASSERTION","filesAnalyzed":false,"primaryPackagePurpose":"APPLICATION"},
	    {"SPDXID":"SPDXRef-Package-lodash","name":"lodash","versionInfo":"3.10.1",
	     "downloadLocation":"NOASSERTION","licenseConcluded":"MIT","licenseDeclared":"MIT",
	     "copyrightText":"NOASSERTION","filesAnalyzed":false,
	     "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/lodash@3.10.1"}]}
	  ],
	  "relationships":[
	    {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-Package-root"},
	    {"spdxElementId":"SPDXRef-Package-root","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-Package-lodash"}
	  ]
	}`)

	// Not an SBOM: a corpus directory in the wild holds these too.
	write("notes.json", `{"todo":"nothing"}`)

	return dir
}

func buildIndex(t *testing.T, dir string) (*Index, *Collected) {
	t.Helper()
	collected, err := Collect(CollectOptions{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return NewIndex(collected.Documents), collected
}

func TestCollect(t *testing.T) {
	dir := corpusFixture(t)
	_, collected := buildIndex(t, dir)

	if len(collected.Documents) != 3 {
		t.Fatalf("collected %d documents, want 3", len(collected.Documents))
	}
	if len(collected.Failed) != 0 {
		t.Errorf("unexpected failures: %+v", collected.Failed)
	}
	// notes.json does not look like an SBOM, so a walk never reads it.
	for _, d := range collected.Documents {
		if filepath.Base(d.Source.Path) == "notes.json" {
			t.Error("a non-SBOM file was collected")
		}
	}
}

func TestCollectGlobAndMissingPath(t *testing.T) {
	dir := corpusFixture(t)

	collected, err := Collect(CollectOptions{Paths: []string{filepath.Join(dir, "*.cdx.json")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(collected.Documents) != 2 {
		t.Errorf("glob collected %d, want the 2 CycloneDX documents", len(collected.Documents))
	}

	if _, err := Collect(CollectOptions{Paths: []string{filepath.Join(dir, "nope.json")}}); err == nil {
		t.Error("a missing path was accepted")
	}
	if _, err := Collect(CollectOptions{Paths: []string{filepath.Join(dir, "*.nope")}}); err == nil {
		t.Error("a glob matching nothing was accepted")
	}
}

// TestCollectReportsUnreadable pins that a corpus query says what it could not
// read. Silently answering from fewer documents than the user pointed at turns
// "no results" into a wrong answer.
func TestCollectReportsUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.cdx.json"),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6",`), 0o644); err != nil {
		t.Fatal(err)
	}
	collected, err := Collect(CollectOptions{Paths: []string{filepath.Join(dir, "broken.cdx.json")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(collected.Failed) != 1 {
		t.Fatalf("Failed = %+v, want the truncated document", collected.Failed)
	}
	if collected.Failed[0].Reason == "" {
		t.Error("a failure was reported with no reason")
	}
}

// TestWhereBlastRadius is the question a triage session asks: which of our
// services carry this package, and where can it actually be changed.
func TestWhereBlastRadius(t *testing.T) {
	idx, _ := buildIndex(t, corpusFixture(t))

	br := idx.Where("lodash")
	if len(br.Locations) != 3 {
		t.Fatalf("lodash found in %d documents, want 3", len(br.Locations))
	}
	// Three versions, ordered oldest-first.
	want := []string{"3.10.1", "4.17.20", "4.17.21"}
	if len(br.Versions) != len(want) {
		t.Fatalf("versions = %v, want %v", br.Versions, want)
	}
	for i, v := range want {
		if br.Versions[i] != v {
			t.Errorf("versions = %v, want %v (ordered oldest-first)", br.Versions, want)
			break
		}
	}
	// Every document depends on lodash directly.
	if br.DirectCount != 3 {
		t.Errorf("DirectCount = %d, want 3", br.DirectCount)
	}
	if br.TransitiveCount != 0 || br.UnknownCount != 0 {
		t.Errorf("transitive = %d, unknown = %d, want 0 and 0", br.TransitiveCount, br.UnknownCount)
	}

	// left-pad is pulled in by express, not by the service.
	lp := idx.Where("left-pad")
	if lp.DirectCount != 0 || lp.TransitiveCount != 1 {
		t.Errorf("left-pad direct = %d transitive = %d, want 0 and 1",
			lp.DirectCount, lp.TransitiveCount)
	}

	// Deployment labels travel with the answer, which is the point of tagging.
	var sawCluster bool
	for _, l := range br.Locations {
		if l.Deployment.Cluster != "" {
			sawCluster = true
		}
	}
	if !sawCluster {
		t.Error("no location carried a deployment label")
	}
}

func TestWhereByPurlAndMiss(t *testing.T) {
	idx, _ := buildIndex(t, corpusFixture(t))

	// A versioned purl still resolves to the package, not to nothing: the
	// question is about the package, and pinning the version would make the
	// answer depend on which version the asker happened to type.
	if br := idx.Where("pkg:npm/lodash@4.17.20"); len(br.Locations) != 3 {
		t.Errorf("a versioned purl found %d locations, want all 3", len(br.Locations))
	}
	if br := idx.Where("pkg:npm/lodash"); len(br.Locations) != 3 {
		t.Errorf("a versionless purl found %d locations, want 3", len(br.Locations))
	}
	if br := idx.Where("not-a-real-package"); len(br.Locations) != 0 {
		t.Errorf("a miss returned %d locations", len(br.Locations))
	}
}

// TestSkew is the "why do we have five versions of this" question.
func TestSkew(t *testing.T) {
	idx, _ := buildIndex(t, corpusFixture(t))

	entries := idx.Skew()
	if len(entries) != 1 {
		t.Fatalf("skew = %d packages, want just lodash: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Name != "lodash" {
		t.Errorf("skewed package = %q", e.Name)
	}
	if len(e.Versions) != 3 {
		t.Fatalf("lodash at %d versions, want 3", len(e.Versions))
	}
	if e.DocumentCount != 3 {
		t.Errorf("DocumentCount = %d, want 3", e.DocumentCount)
	}
	// Direct count is where the version can actually be changed.
	if e.DirectCount != 3 {
		t.Errorf("DirectCount = %d, want 3", e.DirectCount)
	}
	// Versions ordered, each naming the documents that carry it.
	if e.Versions[0].Version != "3.10.1" {
		t.Errorf("versions not ordered oldest-first: %+v", e.Versions)
	}
	for _, v := range e.Versions {
		if len(v.Documents) == 0 {
			t.Errorf("version %s names no documents", v.Version)
		}
	}
}

// TestSkewIgnoresUnversioned pins that a component with no version is not a
// version disagreement — otherwise every document that omits versions would
// report skew.
func TestSkewIgnoresUnversioned(t *testing.T) {
	dir := t.TempDir()
	for i, body := range []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
		  "components":[{"type":"library","name":"thing","purl":"pkg:npm/thing"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
		  "components":[{"type":"library","name":"thing","purl":"pkg:npm/thing"}]}`,
	} {
		name := filepath.Join(dir, "doc"+string(rune('a'+i))+".cdx.json")
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	idx, _ := buildIndex(t, dir)
	if entries := idx.Skew(); len(entries) != 0 {
		t.Errorf("unversioned components reported as skew: %+v", entries)
	}
}

func TestSearchFacets(t *testing.T) {
	idx, _ := buildIndex(t, corpusFixture(t))

	hits := idx.Search("lodash", 25)
	if len(hits.Components) != 1 {
		t.Fatalf("components = %+v, want lodash", hits.Components)
	}
	if hits.Components[0].Documents != 3 {
		t.Errorf("lodash documents = %d, want 3", hits.Components[0].Documents)
	}

	// A vulnerability search must match the description, not only the id:
	// "log4shell" is how people refer to CVE-2021-44228.
	byName := idx.Search("log4shell", 25)
	if len(byName.Vulnerabilities) != 1 || byName.Vulnerabilities[0].ID != "CVE-2021-44228" {
		t.Errorf("description search = %+v, want CVE-2021-44228", byName.Vulnerabilities)
	}
	if byName.Vulnerabilities[0].Severity != "critical" {
		t.Errorf("severity = %q", byName.Vulnerabilities[0].Severity)
	}

	// Licences are a facet, so "which of our services ship AGPL" is answerable.
	lic := idx.Search("AGPL", 25)
	if len(lic.Licenses) != 1 || lic.Licenses[0].License != "AGPL-3.0-only" {
		t.Errorf("licence search = %+v", lic.Licenses)
	}

	// Documents match on subject.
	docs := idx.Search("checkout", 25)
	if len(docs.Documents) != 1 {
		t.Errorf("document search = %+v", docs.Documents)
	}
}

// TestSearchLimitsPerFacet pins that a facet with many hits does not bury the
// facets with few.
func TestSearchLimitsPerFacet(t *testing.T) {
	idx, _ := buildIndex(t, corpusFixture(t))

	hits := idx.Search("lo", 1)
	if len(hits.Components) > 1 {
		t.Errorf("limit not applied to components: %d", len(hits.Components))
	}
	// The total is still reported, so a truncated answer says how much it cut.
	if hits.Totals["components"] < len(hits.Components) {
		t.Errorf("Totals = %v, want at least the shown count", hits.Totals)
	}
}

func TestSearchRejectsTooShort(t *testing.T) {
	idx, _ := buildIndex(t, corpusFixture(t))
	hits := idx.Search("l", 25)
	if len(hits.Components)+len(hits.Documents)+len(hits.Vulnerabilities)+len(hits.Licenses) != 0 {
		t.Error("a one-character query returned results; it matches most of a corpus")
	}
}

func TestSummaries(t *testing.T) {
	idx, _ := buildIndex(t, corpusFixture(t))
	summaries := idx.Summaries()
	if len(summaries) != 3 {
		t.Fatalf("summaries = %d, want 3", len(summaries))
	}

	bySubject := map[string]DocumentSummary{}
	for _, s := range summaries {
		bySubject[s.Subject] = s
	}
	payments, ok := bySubject["payment-service"]
	if !ok {
		t.Fatalf("payment-service missing from %+v", summaries)
	}
	if payments.Components != 3 || payments.Vulnerabilities != 1 {
		t.Errorf("payment-service = %+v", payments)
	}
	if payments.Deployment.Cluster != "prod-eu" {
		t.Errorf("deployment = %+v, want cluster prod-eu", payments.Deployment)
	}
	// The SPDX document is summarised alongside the CycloneDX ones.
	if docs, ok := bySubject["docs-site"]; !ok || docs.Format != FormatSPDX {
		t.Errorf("docs-site = %+v, want an SPDX document", docs)
	}
}

package bom

import (
	"encoding/json"
	"testing"
)

// testCDX returns a CycloneDX JSON document. The fields every test document
// shares are set here, so callers state only the part they vary.
func testCDX(t *testing.T, doc cdxTestDoc) string {
	t.Helper()
	doc.BOMFormat = "CycloneDX"
	if doc.SpecVersion == "" {
		doc.SpecVersion = "1.6"
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return marshalTestDoc(t, doc)
}

// testSPDX returns an SPDX 2.3 JSON document.
func testSPDX(t *testing.T, doc spdxTestDoc) string {
	t.Helper()
	doc.SPDXVersion = "SPDX-2.3"
	doc.DataLicense = "CC0-1.0"
	doc.SPDXID = "SPDXRef-DOCUMENT"
	return marshalTestDoc(t, doc)
}

// testCDXTruncated returns CycloneDX bytes cut off mid-document, for tests that
// need a file which looks like an SBOM but cannot be read.
func testCDXTruncated() string {
	return `{"bomFormat":"CycloneDX","specVersion":"1.6",`
}

// testSPDX3 returns an SPDX 3.0 document, a shape this reader refuses rather
// than mis-parses, for tests that need an unsupported document.
func testSPDX3() string {
	return `{"spdxVersion":"SPDX-3.0","SPDXID":"SPDXRef-DOCUMENT"}`
}

func marshalTestDoc(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal test document: %v", err)
	}
	return string(b)
}

type cdxTestDoc struct {
	BOMFormat       string                 `json:"bomFormat"`
	SpecVersion     string                 `json:"specVersion"`
	Version         int                    `json:"version"`
	SerialNumber    string                 `json:"serialNumber,omitempty"`
	Metadata        *cdxTestMetadata       `json:"metadata,omitempty"`
	Components      []cdxTestComponent     `json:"components,omitempty"`
	Dependencies    []cdxTestDependency    `json:"dependencies,omitempty"`
	Vulnerabilities []cdxTestVulnerability `json:"vulnerabilities,omitempty"`
}

type cdxTestMetadata struct {
	Timestamp  string            `json:"timestamp,omitempty"`
	Component  *cdxTestComponent `json:"component,omitempty"`
	Properties []cdxTestProperty `json:"properties,omitempty"`
}

type cdxTestProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxTestComponent struct {
	Type     string           `json:"type"`
	BOMRef   string           `json:"bom-ref,omitempty"`
	Name     string           `json:"name"`
	Version  string           `json:"version,omitempty"`
	Purl     string           `json:"purl,omitempty"`
	Licenses []cdxTestLicense `json:"licenses,omitempty"`
}

type cdxTestLicense struct {
	License *cdxTestLicenseID `json:"license,omitempty"`
}

type cdxTestLicenseID struct {
	ID string `json:"id"`
}

type cdxTestDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxTestVulnerability struct {
	ID          string          `json:"id"`
	Description string          `json:"description,omitempty"`
	Ratings     []cdxTestRating `json:"ratings,omitempty"`
	Affects     []cdxTestAffect `json:"affects,omitempty"`
}

type cdxTestRating struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

type cdxTestAffect struct {
	Ref string `json:"ref"`
}

type spdxTestDoc struct {
	SPDXVersion       string                 `json:"spdxVersion"`
	DataLicense       string                 `json:"dataLicense"`
	SPDXID            string                 `json:"SPDXID"`
	Name              string                 `json:"name"`
	DocumentNamespace string                 `json:"documentNamespace"`
	CreationInfo      spdxTestCreationInfo   `json:"creationInfo"`
	DocumentDescribes []string               `json:"documentDescribes,omitempty"`
	Packages          []spdxTestPackage      `json:"packages,omitempty"`
	Relationships     []spdxTestRelationship `json:"relationships,omitempty"`
}

type spdxTestCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxTestPackage struct {
	SPDXID                string                `json:"SPDXID"`
	Name                  string                `json:"name"`
	VersionInfo           string                `json:"versionInfo"`
	DownloadLocation      string                `json:"downloadLocation"`
	LicenseConcluded      string                `json:"licenseConcluded"`
	LicenseDeclared       string                `json:"licenseDeclared"`
	CopyrightText         string                `json:"copyrightText"`
	FilesAnalyzed         bool                  `json:"filesAnalyzed"`
	PrimaryPackagePurpose string                `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs          []spdxTestExternalRef `json:"externalRefs,omitempty"`
}

type spdxTestExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxTestRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

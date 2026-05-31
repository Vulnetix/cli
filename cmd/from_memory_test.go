package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulnetix/cli/v3/internal/cdx"
)

func TestBuildPkgFromComponentDerivesIdentityFromPURL(t *testing.T) {
	pkg := buildPkgFromComponent(cdx.Component{
		Type:    "library",
		Name:    "babel-traverse",
		Version: "0.0.0",
		Purl:    "pkg:npm/%40babel/traverse@7.25.9?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fbabel%2Fbabel.git#packages/babel-traverse",
	})

	assert.Equal(t, "@babel/traverse", pkg.Name)
	assert.Equal(t, "7.25.9", pkg.Version)
	assert.Equal(t, "npm", pkg.Ecosystem)
	assert.Equal(t, "pkg:npm/babel/traverse@7.25.9", cdx.BuildLocalPurl(pkg.Name, pkg.Version, pkg.Ecosystem))
}

func TestBuildPkgFromComponentKeepsVulnetixProperties(t *testing.T) {
	pkg := buildPkgFromComponent(cdx.Component{
		Type:    "library",
		Name:    "requests",
		Version: "2.32.3",
		Purl:    "pkg:pypi/requests@2.32.3",
		Properties: []cdx.Property{
			{Name: "vulnetix:ecosystem", Value: "pypi"},
			{Name: "vulnetix:scope", Value: "production"},
			{Name: "vulnetix:source-file", Value: "./requirements.txt"},
		},
	})

	assert.Equal(t, "requests", pkg.Name)
	assert.Equal(t, "2.32.3", pkg.Version)
	assert.Equal(t, "pypi", pkg.Ecosystem)
	assert.Equal(t, "production", pkg.Scope)
	assert.Equal(t, "./requirements.txt", pkg.SourceFile)
}

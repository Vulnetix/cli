package analyze

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsEgressHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		why  string
	}{
		{"viperhappenscope.com", true, "an ordinary registrable name"},
		{"cdn.acme.io", true, "a subdomain is still a destination"},
		{"https://api.stripe.com/v1/charges", true, "a URL is normalised to its host"},
		{"registry.npmjs.org:443", true, "a port is not part of the name"},
		{"acme.co.uk.", true, "a trailing root dot is legal"},

		{"yaml.v3", false, "a version suffix is not a TLD"},
		{"core.min.js", false, "a file name is not a host"},
		{"settings.local.json", false, "nor is a config file"},
		{"lodash", false, "one label is not a host"},
		{"10.0.0.1", false, "an address is not a DNS record"},
		{"-acme.com", false, "a label may not start with a hyphen"},
		{"acme..com", false, "an empty label is not legal"},

		{"localhost", false, "reserved"},
		{"db.internal", false, "RFC 8375 private use"},
		{"api.test", false, "RFC 2606 reserved"},
		{"example.com", false, "RFC 2606 reserved"},
		{"foo.example", false, "RFC 6761 reserved"},

		{"www.w3.org", false, "an XML namespace, never fetched"},
		{"schemas.xmlsoap.org", false, "same"},
		{"opensource.org", false, "a licence URL is not egress"},
		{"en.wikipedia.org", false, "a doc link is not egress"},
	}

	for _, c := range cases {
		require.Equalf(t, c.want, isEgressHost(c.in), "%s — %s", c.in, c.why)
	}
}

// The gate that keeps registry packages out of the egress vocabulary. `socket.io`
// is fetched from the npm registry; nothing ever resolves it.
func TestEgressHostFromDependency(t *testing.T) {
	host, ok := egressHostFromDependency("pkg:golang/viperhappenscope.com@v1.2.0", "viperhappenscope.com")
	require.True(t, ok)
	require.Equal(t, "viperhappenscope.com", host)

	_, ok = egressHostFromDependency("pkg:npm/socket.io@4.7.5", "socket.io")
	require.False(t, ok, "an npm package named like a host stays a package")

	_, ok = egressHostFromDependency("pkg:pypi/zope.interface@6.0", "zope.interface")
	require.False(t, ok, ".interface is not a TLD either, but the registry gate comes first")

	_, ok = egressHostFromDependency("pkg:golang/github.com/spf13/viper@v1.18.2", "viper")
	require.False(t, ok, "the module's own host is provenance, not egress")

	host, ok = egressHostFromDependency("pkg:generic/acme-tools.io@1.0.0", "acme-tools.io")
	require.True(t, ok, "a generic package is fetched from wherever it says")
	require.Equal(t, "acme-tools.io", host)
}

func TestClassifyEgressSource(t *testing.T) {
	require.Equal(t, egressSourceCI, classifyEgressSource(".github/workflows/release.yml"))
	require.Equal(t, egressSourceCI, classifyEgressSource(".gitlab-ci.yml"))
	require.Equal(t, egressSourceContainer, classifyEgressSource("build/Dockerfile"))
	require.Equal(t, egressSourceContainer, classifyEgressSource("docker-compose.yaml"))
	require.Equal(t, egressSourceIaC, classifyEgressSource("terraform/main.tf"))
	require.Equal(t, egressSourceIaC, classifyEgressSource("charts/api/values.yaml"))
	require.Equal(t, egressSourceEnv, classifyEgressSource(".env.production"))
	require.Equal(t, egressSourceManifest, classifyEgressSource("go.sum"))
	require.Equal(t, egressSourceConfig, classifyEgressSource("config/app.yaml"))
	require.Equal(t, egressSourceCode, classifyEgressSource("internal/api/client.go"))
}

func TestNormaliseHost(t *testing.T) {
	require.Equal(t, "api.acme.io", normaliseHost("HTTPS://user:pw@API.acme.io:8443/v1?x=1"))
	require.Equal(t, "acme.io", normaliseHost("acme.io."))
}

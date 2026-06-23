package cyclonedx

import "testing"

func TestParsePurl(t *testing.T) {
	cases := []struct {
		purl                       string
		wantEco, wantName, wantVer string
	}{
		{"pkg:golang/github.com%2Fcloudflare%2Fcircl@1.6.3", "golang", "github.com/cloudflare/circl", "1.6.3"},
		{"pkg:npm/%40scope%2Fpkg@1.0.0", "npm", "@scope/pkg", "1.0.0"},
		{"pkg:github-actions/actions%2Fcheckout@v5", "github-actions", "actions/checkout", "v5"},
		{"pkg:npm/lodash@4.17.21", "npm", "lodash", "4.17.21"},
		{"pkg:pypi/django@4.2?extension=tar.gz", "pypi", "django", "4.2"}, // qualifiers dropped
		{"pkg:cargo/serde@1.0.0#sub/path", "cargo", "serde", "1.0.0"},     // subpath dropped
		{"pkg:docker/library%2Fnginx@1.25", "docker", "library/nginx", "1.25"},
		{"not-a-purl", "", "", ""},
	}
	for _, c := range cases {
		eco, name, ver := ParsePurl(c.purl)
		if eco != c.wantEco || name != c.wantName || ver != c.wantVer {
			t.Errorf("ParsePurl(%q) = (%q,%q,%q), want (%q,%q,%q)",
				c.purl, eco, name, ver, c.wantEco, c.wantName, c.wantVer)
		}
	}
}

package grafana

import "testing"

func TestAuthHeader(t *testing.T) {
	c := New("https://grafana.local", "glsa_@@sample:[A-Za-z0-9]{32}@@_@@sample:[a-f0-9]{8}@@")
	if c.header() == "" {
		t.Fatal("empty")
	}
}

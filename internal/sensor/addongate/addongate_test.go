package addongate

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestFromResponse(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		denied    bool
		wantAddon string
	}{
		{"402 with the add-on named", 402, `{"error":"add-on required","addon":"soc_intelligence","planLocked":true}`, true, "soc_intelligence"},
		{"402 naming it only in _entitlements", 402, `{"planLocked":true,"_entitlements":{"addon":"package_firewall"}}`, true, "package_firewall"},
		{"402 with no body is still a denial", 402, ``, true, ""},
		{"402 with a html body", 402, `<html>pay up</html>`, true, ""},
		{"200 soft marker", 200, `{"planLocked":true,"feature":"runtime-sensors","addon":"soc_intelligence"}`, true, "soc_intelligence"},
		{"200 soft marker inside _entitlements", 200, `{"planLocked":true,"_entitlements":{"plan":"pro","addon":"soc_intelligence"}}`, true, "soc_intelligence"},
		{"200 marker with no add-on (plan floor)", 200, `{"planLocked":true,"requiredPlan":"teams"}`, true, ""},
		{"200 normal answer", 200, `{"accepted":1}`, false, ""},
		{"200 planLocked false", 200, `{"planLocked":false,"config":{}}`, false, ""},
		{"200 empty body", 200, ``, false, ""},
		{"200 not json", 200, `ok`, false, ""},
		{"500 is not an add-on denial", 500, `{"error":"boom"}`, false, ""},
		{"403 is not an add-on denial", 403, `{"error":"no"}`, false, ""},
		{"204", 204, ``, false, ""},
	}
	for _, c := range cases {
		e := FromResponse("POST", "/v1/runtime/events", c.status, []byte(c.body))
		if (e != nil) != c.denied {
			t.Errorf("%s: denial = %v, want %v", c.name, e != nil, c.denied)

			continue
		}
		if e != nil && e.Addon != c.wantAddon {
			t.Errorf("%s: addon = %q, want %q", c.name, e.Addon, c.wantAddon)
		}
	}
}

func TestErrorNamesTheAddon(t *testing.T) {
	e := FromResponse("GET", "/v1/runtime/provisioning/config", http.StatusPaymentRequired, []byte(`{"addon":"soc_intelligence"}`))
	msg := e.Error()
	for _, want := range []string{"SOC Intelligence add-on", "GET /v1/runtime/provisioning/config", "resolve/billing#addons"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
	unnamed := FromResponse("GET", "/x", 402, nil).Error()
	if !strings.Contains(unnamed, "add-on") {
		t.Errorf("an unnamed denial still says add-on: %q", unnamed)
	}
}

func TestIsMatchesWrappedErrors(t *testing.T) {
	var inner error = FromResponse("GET", "/x", 402, nil)
	wrapped := fmt.Errorf("pull: %w", inner)
	if !Is(wrapped) {
		t.Error("Is must see through wrapping")
	}
	if Is(errors.New("HTTP 502")) || Is(nil) {
		t.Error("other errors are not denials")
	}
}

func TestDisplayName(t *testing.T) {
	for kind, want := range map[string]string{
		"soc_intelligence": "SOC Intelligence",
		"package_firewall": "Package Firewall",
		"":                 "required",
		"some_new_thing":   "some_new_thing",
	} {
		if got := DisplayName(kind); got != want {
			t.Errorf("DisplayName(%q) = %q, want %q", kind, got, want)
		}
	}
}

package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/pkg/vdb"
)

func TestLivenessSendsAFailedDialAsStatusZero(t *testing.T) {
	o := livenessObservation(vdb.CliSurfaceTarget{Host: "api.example.com", Method: "GET", PathTemplate: "/v1/items"}, "GET", 0, "", 15000, 1)
	b, _ := json.Marshal(o)
	if !strings.Contains(string(b), `"status":0`) {
		t.Fatalf("a failed dial must be sent as status 0, got %s", b)
	}
}

func TestLivenessKeepsTheRouteMethodApartFromTheProbe(t *testing.T) {
	target := vdb.CliSurfaceTarget{Host: "api.example.com", Method: "post", PathTemplate: "/v1/orders"}
	_, probe, ok := livenessRequest("https", target)
	if !ok || probe != "OPTIONS" {
		t.Fatalf("a POST route is checked with OPTIONS, got %q", probe)
	}
	o := livenessObservation(target, probe, 204, "", 12, 1)
	if o.Method != "POST" || o.ProbeMethod != "OPTIONS" || o.ObservedBy != "cli_liveness" || o.Status == nil || *o.Status != 204 {
		t.Fatalf("got method %q probe %q by %q status %v", o.Method, o.ProbeMethod, o.ObservedBy, o.Status)
	}
	b, _ := json.Marshal(o)
	for _, want := range []string{`"method":"POST"`, `"probeMethod":"OPTIONS"`, `"status":204`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("payload %s lacks %s", b, want)
		}
	}
}

package vdb

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

func TestInputsEncodeUsesTheAPINames(t *testing.T) {
	q := url.Values{}
	Inputs{VulnIDs: []string{"CVE-1", "CVE-2"}, Package: "lodash", Ecosystem: "npm", Version: "4.17.20",
		Vendor: "a", Product: "b", CPE: "cpe:/a:a:b", PURL: "pkg:npm/lodash", TEI: "urn:tei:x", CEL: "true", SWID: "<x/>"}.Encode(q)
	want := map[string][]string{
		"vulnId": {"CVE-1", "CVE-2"}, "package": {"lodash"}, "ecosystem": {"npm"}, "version": {"4.17.20"},
		"vendor": {"a"}, "product": {"b"}, "cpe": {"cpe:/a:a:b"}, "purl": {"pkg:npm/lodash"},
		"tei": {"urn:tei:x"}, "cel": {"true"}, "swid": {"<x/>"},
	}
	for k, v := range want {
		if strings.Join(q[k], ",") != strings.Join(v, ",") {
			t.Errorf("%s = %v, want %v", k, q[k], v)
		}
	}
}

func TestNeedsBody(t *testing.T) {
	if (Inputs{PURL: "pkg:npm/lodash"}).NeedsBody() {
		t.Error("a purl fits a query string")
	}
	if !(Inputs{CEL: "true"}).NeedsBody() || !(Inputs{SWID: "<x/>"}).NeedsBody() {
		t.Error("cel and swid go in a body")
	}
	if !(Inputs{Product: strings.Repeat("x", 2000)}).NeedsBody() {
		t.Error("a long input goes in a body")
	}
}

func TestCountsItemFlattensItsInputs(t *testing.T) {
	b, _ := json.Marshal(DefenceCountsItem{Key: "k", Inputs: Inputs{PURL: "pkg:npm/lodash@1", VulnIDs: []string{"CVE-1"}}})
	if string(b) != `{"key":"k","vulnIds":["CVE-1"],"purl":"pkg:npm/lodash@1"}` {
		t.Errorf("item JSON = %s", b)
	}
}

// fakeAPI answers /v2/defences/counts and the defence searches the way vdb-api
// does, recording what it was sent.
func fakeAPI(t *testing.T, gated bool) (*Client, *[]map[string]any, *[]string) {
	t.Helper()
	var bodies []map[string]any
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		bodies = append(bodies, body)
		switch r.URL.Path {
		case "/v2/defences/counts":
			items, _ := body["items"].([]any)
			out := []any{}
			for _, it := range items {
				m := it.(map[string]any)
				var defs any = []any{map[string]any{"uuid": "u1", "kind": "SNORT", "consoleUrl": "https://www.vulnetix.com/resolve/virtual-patching?dc=u1#catalogue"}}
				if gated {
					defs = nil
				}
				out = append(out, map[string]any{"key": m["key"],
					"virtualPatches":  map[string]any{"total": 1, "byKind": map[string]any{"SNORT": 1}, "defences": defs},
					"countermeasures": map[string]any{"total": 0, "byKind": map[string]any{}, "defences": []any{}}})
			}
			resp := map[string]any{"schemaVersion": "defence-counts/v1", "tier": "pro", "items": out}
			if gated {
				resp["tier"] = "community"
				resp["_entitlements"] = map[string]any{"plan": "community"}
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"total": 0, "virtual-patches": []any{}})
		}
	}))
	t.Cleanup(srv.Close)
	c := NewClientFromCredentials(&auth.Credentials{OrgID: "org", APIKey: "key", Method: auth.DirectAPIKey})
	c.BaseURL = srv.URL
	c.APIVersion = "/v2"
	return c, &bodies, &calls
}

func TestDefenceCountsChunksAndKeepsOrder(t *testing.T) {
	c, bodies, _ := fakeAPI(t, false)
	items := make([]DefenceCountsItem, 230)
	for i := range items {
		items[i] = DefenceCountsItem{Key: string(rune('a' + i%26)), Inputs: Inputs{VulnIDs: []string{"CVE-2021-44228"}}}
	}
	resp, err := c.V2DefenceCounts(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(*bodies) != 3 || len(resp.Items) != 230 {
		t.Fatalf("requests %d, items %d; want 3 and 230", len(*bodies), len(resp.Items))
	}
	for i, it := range resp.Items {
		if it.Key != items[i].Key {
			t.Fatalf("item %d key %q, want %q", i, it.Key, items[i].Key)
		}
	}
	if resp.Gated() || resp.Items[0].VirtualPatches.Defences[0].ConsoleURL == "" {
		t.Error("a Pro answer lists defences with console links")
	}
}

func TestDefenceCountsGatedAnswerKeepsCounts(t *testing.T) {
	c, _, _ := fakeAPI(t, true)
	resp, err := c.V2DefenceCounts([]DefenceCountsItem{{Key: "x", Inputs: Inputs{PURL: "pkg:npm/lodash@4.17.20"}}})
	if err != nil {
		t.Fatal(err)
	}
	vp := resp.Items[0].VirtualPatches
	if !resp.Gated() || vp.Total != 1 || vp.Defences != nil {
		t.Errorf("gated answer: gated=%v total=%d defences=%v", resp.Gated(), vp.Total, vp.Defences)
	}
}

func TestDefenceSearchGoesInABodyOnlyWhenItMust(t *testing.T) {
	c, bodies, calls := fakeAPI(t, false)
	if _, err := c.V2DefenceSearch("virtual-patches", DefenceSearchParams{Inputs: Inputs{PURL: "pkg:npm/lodash@1"}, CveIDs: []string{"CVE-1"}, Kinds: []string{"SNORT"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix((*calls)[0], "GET /v2/virtual-patches?") || !strings.Contains((*calls)[0], "purl=pkg%3Anpm%2Flodash%401") || !strings.Contains((*calls)[0], "vulnId=CVE-1") {
		t.Errorf("GET call = %s", (*calls)[0])
	}
	if _, err := c.V2DefenceSearch("countermeasures", DefenceSearchParams{Inputs: Inputs{CEL: "true"}, Kinds: []string{"SIGMA"}, Limit: 5}); err != nil {
		t.Fatal(err)
	}
	if (*calls)[1] != "POST /v2/countermeasures?" {
		t.Errorf("POST call = %s", (*calls)[1])
	}
	b := (*bodies)[1]
	if b["cel"] != "true" || b["limit"] != float64(5) || b["kind"].([]any)[0] != "SIGMA" {
		t.Errorf("POST body = %v", b)
	}
}

package uplink

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/internal/sensor/addongate"
	"github.com/vulnetix/cli/v4/pkg/auth"
)

type recorder struct {
	bodies map[string]string
	auth   string
	query  string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// The client gzips every body.
	var src io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		if zr, err := gzip.NewReader(req.Body); err == nil {
			src = zr
		}
	}
	body, _ := io.ReadAll(src)
	r.bodies[req.URL.Path] = string(body)
	r.auth = req.Header.Get("Authorization")
	r.query = req.URL.RawQuery
	switch req.URL.Path {
	case "/v1/runtime/sensors/register":
		_, _ = w.Write([]byte(`{"sensorUuid":"s-1"}`))
	case "/v1/runtime/events":
		_, _ = w.Write([]byte(`{"accepted":1,"rejected":["1: bad"]}`))
	case "/v1/runtime/decisions":
		_, _ = w.Write([]byte(`{"decisions":[{"uuid":"d","verdict":"block","decidedAt":50}],"cursor":50}`))
	default:
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"unknown sensor: register first"}`))
	}
}

func client(t *testing.T) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{bodies: map[string]string{}}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)

	return &Client{Endpoint: srv.URL, Creds: &auth.Credentials{Method: auth.SigV4, OrgID: "org", Secret: "s"}, Version: "test"}, rec
}

func TestRegisterDistinguishesUnchangedFromNothingLoaded(t *testing.T) {
	c, rec := client(t)
	ctx := context.Background()

	if _, err := c.Register(ctx, Registration{SensorKey: "k", ComputeKind: "ec2", Mode: "monitor"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.bodies["/v1/runtime/sensors/register"], "ruleLoads") {
		t.Fatal("nil rule loads must be left out, meaning unchanged")
	}

	id, err := c.Register(ctx, Registration{SensorKey: "k", ComputeKind: "ec2", Mode: "monitor", RuleLoads: []RuleLoad{}})
	if err != nil || id != "s-1" {
		t.Fatalf("register = %q %v", id, err)
	}
	var sent map[string]json.RawMessage
	_ = json.Unmarshal([]byte(rec.bodies["/v1/runtime/sensors/register"]), &sent)
	if string(sent["ruleLoads"]) != "[]" || string(sent["sensorKey"]) != `"k"` {
		t.Fatalf("sent = %s", rec.bodies["/v1/runtime/sensors/register"])
	}
	if !strings.HasPrefix(rec.auth, "ApiKey org:") {
		t.Fatalf("auth = %q", rec.auth)
	}
}

func TestPostEventsAndPoll(t *testing.T) {
	c, rec := client(t)
	ctx := context.Background()

	n, rejected, err := c.PostEvents(ctx, "k", []Event{{EventKey: "e"}})
	if err != nil || n != 1 || len(rejected) != 1 {
		t.Fatalf("post = %d %v %v", n, rejected, err)
	}
	if _, _, err := c.PostEvents(ctx, "k", make([]Event, 501)); err == nil {
		t.Fatal("more than 500 events must be split by the caller")
	}

	ds, cursor, err := c.PollDecisions(ctx, "k", 10, 20*time.Second)
	if err != nil || len(ds) != 1 || cursor != 50 {
		t.Fatalf("poll = %v %d %v", ds, cursor, err)
	}
	if !strings.Contains(rec.query, "wait=20") || !strings.Contains(rec.query, "since=10") {
		t.Fatalf("query = %s", rec.query)
	}
}

func TestServerErrorIsReported(t *testing.T) {
	c, _ := client(t)
	err := c.do(context.Background(), http.MethodGet, "/v1/runtime/other", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "register first") {
		t.Fatalf("err = %v", err)
	}
}

func TestSensorCredentialAndGoodbye(t *testing.T) {
	c, rec := client(t)
	c.Authorization = func() string { return "Sensor dev:secret" }
	rec.bodies["x"] = ""
	err := c.Goodbye(context.Background(), "k", "signal", "terminated")
	// The recorder answers unknown paths with 409; the request is what is checked.
	_ = err
	if rec.auth != "Sensor dev:secret" {
		t.Fatalf("auth = %q, want the Sensor credential over Creds", rec.auth)
	}
	var sent map[string]string
	_ = json.Unmarshal([]byte(rec.bodies["/v1/runtime/sensors/goodbye"]), &sent)
	if sent["sensorKey"] != "k" || sent["reason"] != "signal" || sent["detail"] != "terminated" {
		t.Fatalf("goodbye = %v", sent)
	}

	c.Stop()
	delete(rec.bodies, "/v1/runtime/sensors/register")
	if _, err := c.Register(context.Background(), Registration{SensorKey: "k"}); err != ErrStopped {
		t.Fatalf("err = %v, want ErrStopped", err)
	}
	if _, sent := rec.bodies["/v1/runtime/sensors/register"]; sent {
		t.Fatal("a stopped uplink sends nothing")
	}
}

// denial serves every runtime route with the add-on denial the site sends:
// a real 402, or the soft HTTP 200 marker.
func denialServer(t *testing.T, status int) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"add-on required","addon":"soc_intelligence","planLocked":true,"_entitlements":{"addon":"soc_intelligence"}}`))
	}))
	t.Cleanup(srv.Close)

	return &Client{Endpoint: srv.URL, Creds: &auth.Credentials{Method: auth.SigV4, OrgID: "org", Secret: "s"}, Version: "test"}
}

func TestAddonDenialIsAnErrorOnEveryCall(t *testing.T) {
	for _, status := range []int{http.StatusPaymentRequired, http.StatusOK} {
		c := denialServer(t, status)
		ctx := context.Background()

		accepted, _, err := c.PostEvents(ctx, "k", []Event{{EventKey: "e"}})
		if !addongate.Is(err) || accepted != 0 {
			t.Errorf("status %d PostEvents: accepted=%d err=%v; a denial must not look like a send", status, accepted, err)
		}
		if _, err := c.Register(ctx, Registration{SensorKey: "k"}); !addongate.Is(err) {
			t.Errorf("status %d Register err = %v", status, err)
		}
		if _, err := c.PostInventory(ctx, "k", nil); !addongate.Is(err) {
			t.Errorf("status %d PostInventory err = %v", status, err)
		}
		page, err := c.PollDecisionPage(ctx, "k", 7, time.Second)
		if !addongate.Is(err) || page.Cursor != 7 || len(page.Decisions) != 0 {
			t.Errorf("status %d PollDecisionPage: %+v %v", status, page, err)
		}
		var ae *addongate.Error
		if errors.As(err, &ae) {
			if ae.Addon != "soc_intelligence" || strings.Contains(err.Error(), "sensorKey") {
				t.Errorf("status %d: addon=%q msg=%q (the query string must not leak into the message)", status, ae.Addon, err.Error())
			}
		}
	}
}

func TestOrdinaryFailuresAreNotAddonDenials(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusConflict, http.StatusForbidden} {
		c := denialServer(t, status)
		_, _, err := c.PostEvents(context.Background(), "k", []Event{{EventKey: "e"}})
		if err == nil || addongate.Is(err) {
			t.Errorf("status %d: err = %v, want a plain error", status, err)
		}
	}
}

func TestPostInventoryReportSaysHowCompleteItIs(t *testing.T) {
	c, rec := client(t)
	ctx := context.Background()
	no := false
	_, _ = c.PostInventoryReport(ctx, "k", InventoryReport{Complete: &no, Warnings: []string{"var/lib/rpm/rpmdb.sqlite: locked"}})
	var sent map[string]json.RawMessage
	_ = json.Unmarshal([]byte(rec.bodies["/v1/runtime/inventory"]), &sent)
	if string(sent["complete"]) != "false" || !strings.Contains(string(sent["warnings"]), "rpmdb") || string(sent["packages"]) != "[]" {
		t.Fatalf("sent = %s", rec.bodies["/v1/runtime/inventory"])
	}
	// The plain post says nothing about completeness, as before.
	_, _ = c.PostInventory(ctx, "k", nil)
	sent = nil
	_ = json.Unmarshal([]byte(rec.bodies["/v1/runtime/inventory"]), &sent)
	for _, k := range []string{"complete", "warnings", "unsupported"} {
		if _, ok := sent[k]; ok {
			t.Errorf("plain post sent %s: %s", k, rec.bodies["/v1/runtime/inventory"])
		}
	}
}

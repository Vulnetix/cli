package uplink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

type recorder struct {
	bodies map[string]string
	auth   string
	query  string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
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

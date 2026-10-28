package lambdaext

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

// fakeRuntime serves queued invocations and records responses.
type fakeRuntime struct {
	mu        sync.Mutex
	queue     []string
	responses map[string]string
}

func (f *fakeRuntime) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == nextPath:
		id := string(rune('a' + len(f.responses) + len(f.queue)))
		ev := f.queue[0]
		f.queue = f.queue[1:]
		w.Header().Set("Lambda-Runtime-Aws-Request-Id", "req-"+id+"-"+string(rune('0'+len(f.queue))))
		_, _ = w.Write([]byte(ev))
	case strings.HasSuffix(r.URL.Path, "/response"):
		b, _ := io.ReadAll(r.Body)
		f.responses[r.URL.Path] = string(b)
		w.WriteHeader(http.StatusAccepted)
	case strings.HasPrefix(r.URL.Path, extensionAPI+"/register"):
		w.Header().Set("Lambda-Extension-Identifier", "ext-1")
	case strings.HasPrefix(r.URL.Path, extensionAPI+"/event/next"):
		_, _ = w.Write([]byte(`{"eventType":"SHUTDOWN"}`))
	}
}

func setup(t *testing.T, mode decide.Mode, queue ...string) (*RuntimeProxy, *fakeRuntime, *[]uplink.Event) {
	t.Helper()
	rt := &fakeRuntime{queue: queue, responses: map[string]string{}}
	srv := httptest.NewServer(rt)
	t.Cleanup(srv.Close)
	set, _ := engine.Compile([]feed.Rule{{RuleTable: "virtual_patch", RuleUUID: "vp", RuleType: "MODSECURITY", DeployMode: "block",
		Body: `SecRule ARGS "@contains ../" "id:910001,phase:2,deny"`}})
	v := decide.New(mode, decide.Config{})
	v.SetRules([]decide.Rule{{Ref: decide.RuleRef{Table: "virtual_patch", UUID: "vp"}, Mode: decide.Block, Verified: true}})
	var events []uplink.Event

	return &RuntimeProxy{Upstream: strings.TrimPrefix(srv.URL, "http://"), Rules: func() *engine.Set { return set }, Verdicts: v,
		Report: func(e uplink.Event) { events = append(events, e) }}, rt, &events
}

const attack = `{"version":"2.0","rawPath":"/download","rawQueryString":"f=../../etc/passwd","headers":{"host":"api.example"},"requestContext":{"http":{"method":"GET","sourceIp":"203.0.113.5"}}}`
const clean = `{"httpMethod":"GET","path":"/ok","queryStringParameters":{"a":"b"},"headers":{"Host":"api.example"},"requestContext":{"identity":{"sourceIp":"198.51.100.1"}}}`

func TestABlockedInvocationIsAnsweredAndTheNextOneHandedOver(t *testing.T) {
	p, rt, events := setup(t, decide.Enforce, attack, clean)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, nextPath, nil))

	if w.Body.String() != clean {
		t.Fatalf("the runtime should get the clean invocation, got %s", w.Body.String())
	}
	if len(rt.responses) != 1 {
		t.Fatalf("responses = %v", rt.responses)
	}
	for _, body := range rt.responses {
		if !strings.Contains(body, `"statusCode":403`) {
			t.Fatalf("refusal = %s", body)
		}
	}
	if len(*events) != 1 || (*events)[0].Action != "blocked" {
		t.Fatalf("events = %+v", *events)
	}
}

func TestMonitorPassesTheAttackThrough(t *testing.T) {
	p, rt, events := setup(t, decide.Monitor, attack)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, nextPath, nil))
	if w.Body.String() != attack || len(rt.responses) != 0 {
		t.Fatal("monitor answers nothing on the function's behalf")
	}
	if len(*events) != 1 || (*events)[0].Action != "allowed" {
		t.Fatalf("events = %+v", *events)
	}
}

func TestNonHTTPEventsPassUntouched(t *testing.T) {
	sqs := `{"Records":[{"eventSource":"aws:sqs","body":"../../x"}]}`
	p, _, events := setup(t, decide.Enforce, sqs)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, nextPath, nil))
	if w.Body.String() != sqs || len(*events) != 0 {
		t.Fatal("an SQS event is not an HTTP request")
	}
}

func TestHTTPEventShapes(t *testing.T) {
	req, _, ok := HTTPEvent([]byte(attack))
	if !ok || req.Method != "GET" || req.URL.Path != "/download" || req.URL.Query().Get("f") != "../../etc/passwd" || req.RemoteAddr != "203.0.113.5:0" {
		t.Fatalf("v2 = %+v %v", req, ok)
	}
	req, _, ok = HTTPEvent([]byte(clean))
	if !ok || req.URL.Query().Get("a") != "b" || req.Host != "api.example" {
		t.Fatalf("v1 = %+v", req)
	}
	_, body, ok := HTTPEvent([]byte(`{"httpMethod":"POST","path":"/u","body":"aGk=","isBase64Encoded":true}`))
	if !ok || string(body) != "hi" {
		t.Fatalf("base64 body = %q", body)
	}
}

func TestRegisterAndEvents(t *testing.T) {
	rt := &fakeRuntime{responses: map[string]string{}}
	srv := httptest.NewServer(rt)
	defer srv.Close()
	api := strings.TrimPrefix(srv.URL, "http://")
	id, err := Register(context.Background(), http.DefaultClient, api, "vulnetix-sensor")
	if err != nil || id != "ext-1" {
		t.Fatalf("register = %q %v", id, err)
	}
	if err := Events(context.Background(), http.DefaultClient, api, id, nil); err != nil {
		t.Fatal(err)
	}
}

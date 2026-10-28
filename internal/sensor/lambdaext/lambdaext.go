// Package lambdaext runs the sensor inside AWS Lambda as an external
// extension.
//
// Lambda gives the sensor no kernel hooks and no port in front of the
// function, so it uses the one seam Lambda does offer: the Runtime API. The
// layer's exec wrapper points the function's runtime at the sensor
// (AWS_LAMBDA_RUNTIME_API=127.0.0.1:<port>), and the sensor forwards every
// call to the real Runtime API. When the runtime asks for its next invocation,
// the sensor inspects the event first: an API Gateway or function URL event is
// an HTTP request, and runs through the same engines and verdicts as the
// inbound proxy. A blocked or held request is answered with a 403 response on
// the function's behalf, the handler never sees it, and the sensor fetches the
// next invocation for the runtime.
//
// Anything that is not an HTTP event passes through untouched, as does every
// event when the rules have not loaded or inspection fails.
package lambdaext

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

const (
	extensionAPI = "/2020-01-01/extension"
	nextPath     = "/2018-06-01/runtime/invocation/next"
)

// Register registers the extension for INVOKE and SHUTDOWN and returns its id.
func Register(ctx context.Context, client *http.Client, runtimeAPI, name string) (string, error) {
	body := strings.NewReader(`{"events":["INVOKE","SHUTDOWN"]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+runtimeAPI+extensionAPI+"/register", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Lambda-Extension-Name", name)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("register: HTTP %d", resp.StatusCode)
	}
	id := resp.Header.Get("Lambda-Extension-Identifier")
	if id == "" {
		return "", errors.New("register: no extension id")
	}

	return id, nil
}

// Events blocks on the extension event stream, calling onInvoke after each
// INVOKE, and returns when Lambda says SHUTDOWN or ctx ends.
func Events(ctx context.Context, client *http.Client, runtimeAPI, id string, onInvoke func()) error {
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+runtimeAPI+extensionAPI+"/event/next", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Lambda-Extension-Identifier", id)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		var ev struct {
			EventType string `json:"eventType"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ev)
		_ = resp.Body.Close()
		switch ev.EventType {
		case "SHUTDOWN":
			return nil
		case "INVOKE":
			if onInvoke != nil {
				onInvoke()
			}
		}
	}

	return nil
}

// RuntimeProxy is the Runtime API as the function's runtime sees it.
type RuntimeProxy struct {
	// Upstream is the real Runtime API, host:port.
	Upstream string
	Rules    func() *engine.Set
	Verdicts *decide.Engine
	Report   func(uplink.Event)
	Client   *http.Client
	Now      func() time.Time
}

func (p *RuntimeProxy) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}

	// No timeout: invocation/next blocks until there is work.
	return &http.Client{}
}

func (p *RuntimeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == nextPath {
		p.next(w, r)

		return
	}
	resp, err := p.forward(r.Context(), r.Method, r.URL.RequestURI(), r.Header, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)

		return
	}
	defer func() { _ = resp.Body.Close() }()
	copyResponse(w, resp, nil)
}

// next fetches invocations until one is allowed through, answering refused
// ones on the function's behalf.
func (p *RuntimeProxy) next(w http.ResponseWriter, r *http.Request) {
	for {
		resp, err := p.forward(r.Context(), http.MethodGet, nextPath, r.Header, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)

			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 6<<20+1))
		_ = resp.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)

			return
		}
		requestID := resp.Header.Get("Lambda-Runtime-Aws-Request-Id")

		if refusal := p.inspect(body, resp.Header.Get("Lambda-Runtime-Invoked-Function-Arn")); refusal != nil && requestID != "" {
			if err := p.respond(r.Context(), requestID, refusal); err == nil {
				continue
			}
			log.Printf("sensor: could not answer a refused invocation, passing it through")
		}
		copyResponse(w, resp, body)

		return
	}
}

// inspect returns the response to send instead of running the handler, or
// nil to let the invocation through.
func (p *RuntimeProxy) inspect(event []byte, functionArn string) (out []byte) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("sensor: event inspection failed, passing it through: %v", rec)
			out = nil
		}
	}()
	set := p.Rules()
	if set == nil {
		return nil
	}
	req, body, ok := HTTPEvent(event)
	if !ok {
		return nil
	}
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	subject := clip(req.Method + " " + req.URL.Path)
	refused, until := "", time.Time{}
	for _, hit := range set.InspectRequest(req, body) {
		v := p.Verdicts.Decide(decide.Match{Rule: hit.Rule, Subject: subject, Reversible: true}, now)
		if p.Report != nil {
			ev := uplink.Event{
				EventKey: key(event, hit.Rule.UUID), RuleTable: hit.Rule.Table, RuleUUID: hit.Rule.UUID,
				Lane: "virtual-patch", SubjectKind: "request", Subject: subject, Action: string(v.Action),
				Detail:     map[string]any{"match": clip(hit.Detail), "reason": v.Reason, "function": functionArn},
				ObservedAt: now.UnixMilli(),
			}
			if v.Action == decide.Held {
				ev.HoldExpiresAt = v.HoldUntil.UnixMilli()
			}
			p.Report(ev)
		}
		switch v.Action {
		case decide.Blocked:
			refused = "blocked"
		case decide.Held:
			if refused == "" {
				refused, until = "held", v.HoldUntil
			}
		}
	}
	if refused == "" {
		return nil
	}
	msg := "This request was blocked by the site's security policy.\n"
	if refused == "held" {
		msg = fmt.Sprintf("This request is held for review by the site's security team until %s.\n", until.UTC().Format(time.RFC3339))
	}
	resp, _ := json.Marshal(map[string]any{
		"statusCode": http.StatusForbidden,
		"headers":    map[string]string{"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"},
		"body":       msg,
	})

	return resp
}

func (p *RuntimeProxy) respond(ctx context.Context, requestID string, body []byte) error {
	path := "/2018-06-01/runtime/invocation/" + url.PathEscape(requestID) + "/response"
	resp, err := p.forward(ctx, http.MethodPost, path, http.Header{"Content-Type": {"application/json"}}, bytes.NewReader(body))
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("response: HTTP %d", resp.StatusCode)
	}

	return nil
}

func (p *RuntimeProxy) forward(ctx context.Context, method, uri string, header http.Header, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+p.Upstream+uri, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	return p.client().Do(req)
}

func copyResponse(w http.ResponseWriter, resp *http.Response, body []byte) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if body != nil {
		_, _ = w.Write(body)

		return
	}
	_, _ = io.Copy(w, resp.Body)
}

// HTTPEvent reads an API Gateway (REST v1 or HTTP v2) or function URL event as
// an HTTP request. ok is false for any other event.
func HTTPEvent(event []byte) (*http.Request, []byte, bool) {
	var ev struct {
		HTTPMethod            string              `json:"httpMethod"`
		Path                  string              `json:"path"`
		RawPath               string              `json:"rawPath"`
		RawQueryString        string              `json:"rawQueryString"`
		Headers               map[string]string   `json:"headers"`
		MultiValueQuery       map[string][]string `json:"multiValueQueryStringParameters"`
		QueryStringParameters map[string]string   `json:"queryStringParameters"`
		Body                  string              `json:"body"`
		IsBase64Encoded       bool                `json:"isBase64Encoded"`
		RequestContext        struct {
			HTTP struct {
				Method   string `json:"method"`
				SourceIP string `json:"sourceIp"`
			} `json:"http"`
			Identity struct {
				SourceIP string `json:"sourceIp"`
			} `json:"identity"`
		} `json:"requestContext"`
	}
	if json.Unmarshal(event, &ev) != nil {
		return nil, nil, false
	}
	method, path, query, source := ev.HTTPMethod, ev.Path, "", ev.RequestContext.Identity.SourceIP
	if method == "" && ev.RequestContext.HTTP.Method != "" {
		method, path, query, source = ev.RequestContext.HTTP.Method, ev.RawPath, ev.RawQueryString, ev.RequestContext.HTTP.SourceIP
	} else {
		q := url.Values{}
		for k, vs := range ev.MultiValueQuery {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		if len(q) == 0 {
			for k, v := range ev.QueryStringParameters {
				q.Set(k, v)
			}
		}
		query = q.Encode()
	}
	if method == "" || path == "" {
		return nil, nil, false
	}
	target := path
	if query != "" {
		target += "?" + query
	}
	var body []byte
	if ev.Body != "" {
		body = []byte(ev.Body)
		if ev.IsBase64Encoded {
			if decoded, err := base64.StdEncoding.DecodeString(ev.Body); err == nil {
				body = decoded
			}
		}
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, false
	}
	for k, v := range ev.Headers {
		req.Header.Set(k, v)
	}
	req.Host = req.Header.Get("Host")
	if source != "" {
		req.RemoteAddr = source + ":0"
	}

	return req, body, true
}

func key(event []byte, salt string) string {
	return fmt.Sprintf("%x", sha(append(append([]byte{}, event...), salt...)))
}

func clip(s string) string {
	if r := []rune(s); len(r) > 512 {
		return string(r[:512])
	}

	return s
}

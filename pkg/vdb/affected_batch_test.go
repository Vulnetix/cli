package vdb

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

func TestV2AffectedBatchDecodesEachAnswer(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/cli.affected-batch") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var env struct {
			Payload struct {
				Paths []string `json:"paths"`
			} `json:"payload"`
		}
		_ = json.Unmarshal(body, &env)
		got = env.Payload.Paths
		_, _ = w.Write([]byte(`{"meta":{},"data":{"results":[{"status":200,"body":{"identifier":"CVE-1"}},{"status":404,"body":{"error":"not found"}}]}}`))
	}))
	defer srv.Close()
	c := NewClientFromCredentials(&auth.Credentials{OrgID: "00000000-0000-0000-0000-000000000000", APIKey: "k", Method: auth.DirectAPIKey})
	c.BaseURL = srv.URL
	c.APIVersion = "/v2"
	c.Cache = nil

	res := c.V2AffectedBatch(context.Background(), CliEnv{}, []AffectedLookup{
		{ID: "CVE-1", Params: V2QueryParams{PackageName: "lodash", Ecosystem: "npm", Limit: 100}},
		{ID: "GHSA-x", Params: V2QueryParams{PackageName: "lodash", Ecosystem: "npm", Limit: 100}},
	})
	if len(got) != 2 || !strings.HasPrefix(got[0], "/vuln/CVE-1/affected?") || !strings.Contains(got[0], "packageName=lodash") {
		t.Fatalf("sent paths %v", got)
	}
	if res[0].Err != nil || res[0].Data["identifier"] != "CVE-1" {
		t.Fatalf("first answer %+v", res[0])
	}
	var nf *NotFoundError
	if !errors.As(res[1].Err, &nf) {
		t.Fatalf("second answer %+v, want a NotFoundError", res[1])
	}
}

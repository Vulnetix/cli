package vdb

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

// EOL records not sourced from endoflife.date are Pro. Below Pro the VDB
// answers a lookup of one with a 200 planLocked marker; decoding that into the
// typed response used to give an empty product, which `vdb eol product` printed
// as if the product had no releases.
func TestEOLLookupsSurfacePlanLocked(t *testing.T) {
	marker := `{"planLocked":true,"feature":"eol-vendor-lifecycle","requiredPlan":"pro","upgrade":true,"productName":"virtuozzo-hybrid-server"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/eol/products/nodejs") {
			_, _ = w.Write([]byte(`{"timestamp":1,"productName":"nodejs","product":{"name":"nodejs","releases":[]},"release":{"name":"18","isEol":true}}`))
			return
		}
		_, _ = w.Write([]byte(marker))
	}))
	defer srv.Close()
	c := NewClientFromCredentials(&auth.Credentials{OrgID: "00000000-0000-0000-0000-000000000000", APIKey: "k", Method: auth.DirectAPIKey})
	c.BaseURL = srv.URL
	c.APIVersion = "/v1"
	c.Cache = nil

	var locked *PlanLockedError
	if _, err := c.EOLProduct("virtuozzo-hybrid-server"); !errors.As(err, &locked) || locked.Feature != "eol-vendor-lifecycle" || locked.RequiredPlan != "pro" {
		t.Errorf("EOLProduct on a locked product: err = %v, want a PlanLockedError for eol-vendor-lifecycle/pro", err)
	}
	if _, err := c.EOLRelease("virtuozzo-hybrid-server", "7.5"); !errors.As(err, &locked) {
		t.Errorf("EOLRelease on a locked product: err = %v, want a PlanLockedError", err)
	}

	// endoflife.date products are open on every plan and still decode.
	p, err := c.EOLProduct("nodejs")
	if err != nil || p.Product.Name != "nodejs" {
		t.Errorf("EOLProduct(nodejs) = %+v, %v", p, err)
	}
	rel, err := c.EOLRelease("nodejs", "18")
	if err != nil || !rel.Release.IsEol {
		t.Errorf("EOLRelease(nodejs, 18) = %+v, %v", rel, err)
	}
}

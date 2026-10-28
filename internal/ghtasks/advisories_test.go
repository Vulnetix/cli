package ghtasks

import (
	"context"
	"testing"

	"github.com/Vulnetix/vdb-sca-match/ghaudit"
)

func TestAdvisoriesAsksOncePerReferenceAndRecordsFailure(t *testing.T) {
	calls := 0
	a := &Advisories{Lookup: func(_ context.Context, action, ref string) ([]ghaudit.ActionAdvisory, bool) {
		calls++
		switch action + "@" + ref {
		case "tj-actions/changed-files@v45.0.7":
			return []ghaudit.ActionAdvisory{{ID: "CVE-2025-30066"}}, true
		case "broken/x@1.0.0":
			return nil, false
		}
		return nil, true
	}}
	f := a.Func()
	for i := 0; i < 3; i++ {
		if got := f(context.Background(), "tj-actions/changed-files", "v45.0.7", ""); len(got) != 1 || got[0].ID != "CVE-2025-30066" {
			t.Fatalf("advisories = %+v", got)
		}
	}
	if calls != 1 || a.Asked != 1 {
		t.Fatalf("a reference was looked up %d times", calls)
	}
	if a.Failed {
		t.Fatal("no lookup failed yet")
	}
	f(context.Background(), "broken/x", "1.0.0", "")
	if !a.Failed {
		t.Fatal("a failed lookup is recorded")
	}
}

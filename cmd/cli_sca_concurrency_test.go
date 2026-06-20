package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// TestRunSCAJobs_ConcurrencyParity proves the parallel fan-out (Phase B) sends
// the identical set of batches and merges the identical findings as the legacy
// strictly-serial path — i.e. VULNETIX_SCA_CONCURRENCY changes only scheduling,
// not results. Run with -race to catch unsynchronised merge state.
func TestRunSCAJobs_ConcurrencyParity(t *testing.T) {
	run := func(conc string) (received []string, mergedFindings int) {
		t.Setenv("VULNETIX_SCA_CONCURRENCY", conc)
		var smu sync.Mutex
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			purls := reqPurls(r)
			smu.Lock()
			received = append(received, purls...)
			smu.Unlock()
			// Return one finding object per requested purl + a snapshot to anchor to.
			findings := strings.Repeat("{},", len(purls))
			findings = strings.TrimSuffix(findings, ",")
			fmt.Fprintf(w, `{"meta":{"tier":"community"},"data":{"cyclonedx":{"components":[],"vulnerabilities":[]},"findings":[%s],"ingestionSnapshot":{"uuid":"snap-1"}}}`, findings)
		}))
		defer srv.Close()

		client := testSCAClient(srv.URL)
		jobs := []scaJob{
			{purls: []string{"pkg:npm/a@1", "pkg:npm/b@1"}, primary: true, manifestSlot: -1},
			{purls: []string{"pkg:npm/c@1", "pkg:npm/d@1"}, primary: false, manifestSlot: -1},
			{purls: []string{"pkg:npm/e@1", "pkg:npm/f@1"}, primary: false, manifestSlot: -1},
			{purls: []string{"pkg:npm/g@1"}, primary: false, manifestSlot: -1},
		}
		var snapshot *vdb.CliIngestionSnapshot
		buildReq := func(job scaJob) (vdb.CliEnv, vdb.CliSCARequest, bool) {
			req := vdb.CliSCARequest{Purls: job.purls}
			if snapshot != nil {
				req.IngestionSnapshotUuid = snapshot.Uuid
			}
			return vdb.CliEnv{}, req, false
		}
		onResult := func(_ scaJob, resp *vdb.CliResponse[vdb.CliSCAResponse]) {
			if snapshot == nil && resp.Data.IngestionSnapshot != nil {
				snapshot = resp.Data.IngestionSnapshot
			}
			mergedFindings += len(resp.Data.Findings)
		}

		_, anyOK, _ := runSCAJobs(client, jobs, buildReq, onResult, io.Discard)
		if !anyOK {
			t.Fatalf("conc=%s: expected anyOK", conc)
		}
		sort.Strings(received)
		return received, mergedFindings
	}

	serialReceived, serialFindings := run("1")
	parReceived, parFindings := run("6")

	if len(serialReceived) != 7 {
		t.Fatalf("expected all 7 purls served, got %d (%v)", len(serialReceived), serialReceived)
	}
	if strings.Join(serialReceived, ",") != strings.Join(parReceived, ",") {
		t.Errorf("purl set differs by concurrency:\n serial=%v\n par   =%v", serialReceived, parReceived)
	}
	if serialFindings != parFindings || serialFindings != 7 {
		t.Errorf("merged findings differ: serial=%d par=%d (want 7)", serialFindings, parFindings)
	}
}

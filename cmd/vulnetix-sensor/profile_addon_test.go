package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/internal/sensor/agent"
	"github.com/vulnetix/cli/v4/internal/sensor/decide"
	"github.com/vulnetix/cli/v4/internal/sensor/host"
	"github.com/vulnetix/cli/v4/internal/sensor/provision"
)

// An add-on denial on the config pull (402 or the soft 200 marker) keeps the
// config in use, writes nothing to the snapshot file, changes no live setting
// and is logged once with the add-on named.
func TestConfigPollerKeepsTheLastGoodConfigUnderAnAddonDenial(t *testing.T) {
	for _, status := range []int{http.StatusPaymentRequired, http.StatusOK} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"add-on required","addon":"soc_intelligence","planLocked":true}`))
		}))
		var buf bytes.Buffer
		log.SetOutput(&buf)

		a := agent.New(agent.Config{SensorKey: "k", Mode: decide.Guard, Facts: host.Facts{Hostname: "h"}, Logf: func(string, ...any) {}})
		statePath := filepath.Join(t.TempDir(), "config.json")
		snap := provision.Snapshot{ConfigEtag: "e1", Config: provision.Config{Mode: "guard"}}
		poll := configPoller(srv.URL, provision.Credential{Scheme: "Sensor", Value: "s", DeviceUUID: "d"}, snap, map[string]bool{}, statePath, nil, "", "k", nil)

		for i := 0; i < 3; i++ {
			if restart := poll(context.Background(), a); restart {
				t.Fatalf("status %d: a denial must not restart the sensor", status)
			}
		}
		srv.Close()
		log.SetOutput(os.Stderr)

		if a.Mode() != decide.Guard {
			t.Errorf("status %d: mode changed to %s", status, a.Mode())
		}
		if _, err := os.Stat(statePath); err == nil {
			t.Errorf("status %d: an empty snapshot was saved over the last good one", status)
		}
		if n := strings.Count(buf.String(), "SOC Intelligence add-on"); n != 1 {
			t.Errorf("status %d: the add-on was named %d times in %q, want once", status, n, buf.String())
		}
	}
}

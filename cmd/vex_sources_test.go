package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/pkg/auth"
)

func vexSourceYAML(name, body string) string {
	return "apiVersion: vulnetix.com/v1\nkind: VexSource\nmetadata: {name: " + name + "}\nspec:\n" + body
}

func vexConfigRepo(t *testing.T, sources map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range sources {
		writeConfigFile(t, filepath.Join(root, ".vulnetix", "config"), name+".yaml", vexSourceYAML(name, body))
	}
	writeConfigFile(t, root, "vex/openvex.json", openVEXDoc)
	writeConfigFile(t, root, "vex/sbom.json", `{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	return root
}

func TestScanReadsAPathSourceDeclaredInConfig(t *testing.T) {
	root := vexConfigRepo(t, map[string]string{"ci": "  path:\n    path: vex\n"})
	var notes bytes.Buffer
	paths, cleanup, err := resolveVEXInputs(context.Background(), vexInputsOptions{FromConfig: true, Root: root, Notes: &notes})
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 || filepath.Base(paths[0]) != "openvex.json" {
		t.Fatalf("paths %v\n%s", paths, notes.String())
	}
	res, err := runVEXPass(VEXPassOptions{Paths: paths})
	if err != nil || res.Statements != 1 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestDeclaredSourceKeepsItsScopeAndTrust(t *testing.T) {
	orig := vdbCreds
	vdbCreds = nil
	t.Cleanup(func() { vdbCreds = orig })
	root := vexConfigRepo(t, map[string]string{
		"other-repo": "  path:\n    path: vex\n  scope:\n    repos: [acme/elsewhere]\n",
		"stranger":   "  path:\n    path: vex\n  trust:\n    allowedAuthors: [someone-else]\n",
		"console":    "  tea:\n    tei: urn:tei:uuid:example.com:11111111-1111-4111-8111-111111111111\n",
	})
	var notes bytes.Buffer
	paths, cleanup, err := resolveVEXInputs(context.Background(), vexInputsOptions{FromConfig: true, Root: root, Repo: "acme/web", Notes: &notes})
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("a source must not apply more widely than declared: %v\n%s", paths, notes.String())
	}
	if !strings.Contains(notes.String(), "trust.allowedAuthors") || !strings.Contains(notes.String(), "console fetches") {
		t.Fatalf("notes:\n%s", notes.String())
	}
	// The same trusted author, in scope, is applied.
	paths, cleanup2, _ := resolveVEXInputs(context.Background(), vexInputsOptions{FromConfig: true, Root: vexConfigRepo(t, map[string]string{
		"ok": "  path:\n    path: vex\n  scope:\n    repos: [acme/web]\n  trust:\n    allowedAuthors: [ACME]\n",
	}), Repo: "acme/web"})
	defer cleanup2()
	if len(paths) != 1 {
		t.Fatalf("paths %v", paths)
	}
}

func TestNoVEXConfigMeansNoDeclaredSources(t *testing.T) {
	root := vexConfigRepo(t, map[string]string{"ci": "  path:\n    path: vex\n"})
	paths, cleanup, err := resolveVEXInputs(context.Background(), vexInputsOptions{FromConfig: false, Root: root})
	defer cleanup()
	if err != nil || len(paths) != 0 {
		t.Fatalf("%v %v", paths, err)
	}
}

func TestVexFlagFetchesAnHTTPSURL(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vendor/openvex.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(openVEXDoc))
	}))
	defer srv.Close()
	paths, cleanup, err := resolveVEXInputs(context.Background(), vexInputsOptions{
		Explicit: []string{srv.URL + "/vendor/openvex.json", "local/dir"}, HTTP: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || !strings.HasSuffix(paths[0], "openvex.json") || paths[1] != "local/dir" {
		t.Fatalf("paths %v", paths)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil || string(data) != openVEXDoc {
		t.Fatalf("%v %q", err, data)
	}
	cleanup()
	if _, err := os.Stat(paths[0]); err == nil {
		t.Fatal("the download must be removed")
	}
	// A URL the user named that fails is an error, not a quiet gap in the gate.
	if _, _, err := resolveVEXInputs(context.Background(), vexInputsOptions{Explicit: []string{srv.URL + "/missing.json"}, HTTP: srv.Client()}); err == nil {
		t.Fatal("a failed --vex URL must fail the scan")
	}
	if _, _, err := resolveVEXInputs(context.Background(), vexInputsOptions{Explicit: []string{"http://example.com/v.json"}}); err == nil {
		t.Fatal("plain http must be refused")
	}
}

func TestScanCommandsAcceptVEXFlag(t *testing.T) {
	for _, name := range []string{"scan", "sca", "sast", "secrets", "iac", "containers"} {
		ok, err := CommandAcceptsFlag([]string{name}, "vex")
		if err != nil || !ok {
			t.Errorf("vulnetix %s does not accept --vex (%v)", name, err)
		}
	}
}

// A console-fetched source is applied from Vulnetix by an authenticated scan, so
// it is only an unauthenticated one that is told it is not being applied.
func TestConsoleSourceNoteIsForUnauthenticatedScansOnly(t *testing.T) {
	orig := vdbCreds
	t.Cleanup(func() { vdbCreds = orig })
	root := vexConfigRepo(t, map[string]string{"console": "  git:\n    url: https://example.com/vex.git\n"})

	vdbCreds = nil
	var notes bytes.Buffer
	_, cleanup, _ := resolveVEXInputs(context.Background(), vexInputsOptions{FromConfig: true, Root: root, Notes: &notes})
	cleanup()
	if !strings.Contains(notes.String(), "sign in") || !strings.Contains(notes.String(), "git source") {
		t.Errorf("unauthenticated notes:\n%s", notes.String())
	}

	vdbCreds = &auth.Credentials{OrgID: "real-org", APIKey: "real-key", Method: auth.DirectAPIKey}
	notes.Reset()
	_, cleanup, _ = resolveVEXInputs(context.Background(), vexInputsOptions{FromConfig: true, Root: root, Notes: &notes})
	cleanup()
	if notes.Len() != 0 {
		t.Errorf("authenticated notes:\n%s", notes.String())
	}
}

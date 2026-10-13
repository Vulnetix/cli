package vdb

import (
	"encoding/json"
	"testing"
)

func kevPage(total int, items ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"total": total, "items": items})
	return b
}

// Log4Shell is in CISA's catalogue, not Vulnetix's own. The command used to search
// only the latter and report it was not a KEV.
func TestKevGetFindsCVEsInTheAuthorityCatalogues(t *testing.T) {
	pages := map[int][]byte{0: kevPage(3,
		map[string]any{"cveId": "CVE-2010-1", "source": "vulnetix"},
		map[string]any{"cveId": "CVE-2021-44228", "source": "cisa", "product": "Log4j2"},
		map[string]any{"cveId": "CVE-2021-44228", "source": "enisa"})}
	got, err := kevGetFrom(func(off int) ([]byte, error) { return pages[off], nil }, "cve-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	cats, _ := got["catalogues"].([]string)
	if len(cats) != 2 || cats[0] != "cisa" || cats[1] != "enisa" {
		t.Errorf("catalogues = %v", cats)
	}
	if got["product"] != "Log4j2" {
		t.Errorf("should return the first matching row: %v", got)
	}
}

func TestKevGetPagesUntilFoundAndReportsAbsenceHonestly(t *testing.T) {
	full := make([]map[string]any, kevGetPageSize)
	for i := range full {
		full[i] = map[string]any{"cveId": "CVE-X-1", "source": "vulnetix"}
	}
	calls := 0
	pager := func(off int) ([]byte, error) {
		calls++
		if off == 0 {
			return kevPage(kevGetPageSize+1, full...), nil
		}
		return kevPage(kevGetPageSize+1, map[string]any{"cveId": "CVE-2021-44228", "source": "cisa"}), nil
	}
	if _, err := kevGetFrom(pager, "CVE-2021-44228"); err != nil || calls != 2 {
		t.Fatalf("a CVE on the second page must be found: err=%v calls=%d", err, calls)
	}
	_, err := kevGetFrom(pager, "CVE-1999-0001")
	nf, ok := err.(*NotFoundError)
	if !ok || nf.Message == "" {
		t.Fatalf("absence should be a NotFoundError: %v", err)
	}
	if want := "none of the KEV catalogues checked"; !contains(nf.Message, want) {
		t.Errorf("message %q should say it searched every catalogue", nf.Message)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestAnHTMLGatewayErrorIsOneLine(t *testing.T) {
	body := []byte("<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n<center><h1>502 Bad Gateway</h1></center>\n</body>\n</html>\n")
	got := formatAPIError(502, body)
	if !contains(got, "502 Bad Gateway") || !contains(got, "server-side") || contains(got, "<html>") || contains(got, "\n") {
		t.Errorf("gateway page should collapse to one line: %q", got)
	}
	if got := formatAPIError(500, []byte(`{"error":"boom","details":"x"}`)); got != "API error (500): boom - x" {
		t.Errorf("JSON errors are unchanged: %q", got)
	}
	if got := formatAPIError(500, []byte("plain text")); got != "API error (500): plain text" {
		t.Errorf("plain bodies are unchanged: %q", got)
	}
}

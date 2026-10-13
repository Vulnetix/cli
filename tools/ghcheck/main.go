// Throwaway second oracle: for findings OSV cannot confirm, ask GitHub's advisory
// database whether the installed version is inside its vulnerable range.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/vulnetix/cli/v3/internal/versions"
)

type ghAdv struct {
	GHSA  string `json:"ghsa_id"`
	Vulns []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Range string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
}

var rowRE = regexp.MustCompile(`^\s+(\S+)\s+pkg:([a-z]+)/([^@]+)@(\S+)\s+(CVE-\d+-\d+)`)

func main() {
	f, _ := os.Open(os.Args[1])
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	sect := ""
	seen := map[string]bool{}
	tally := map[string]int{}
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "── ") {
			sect = line
			continue
		}
		if !strings.Contains(sect, "FP-unverifiable") && !strings.Contains(sect, "FP-unknown-to-osv") {
			continue
		}
		m := rowRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		repo, eco, name, ver, cve := m[1], m[2], m[3], m[4], m[5]
		if u, err := url.PathUnescape(name); err == nil {
			name = u
		}
		key := eco + name + ver + cve
		if seen[key] {
			continue
		}
		seen[key] = true
		out, err := exec.Command("gh", "api", "advisories?cve_id="+cve+"&per_page=20").Output()
		if err != nil {
			tally["gh-error"]++
			continue
		}
		var advs []ghAdv
		_ = json.Unmarshal(out, &advs)
		verdict := "GH-has-no-entry-for-package"
		detail := ""
		for _, a := range advs {
			for _, v := range a.Vulns {
				if !strings.EqualFold(v.Package.Name, name) {
					continue
				}
				rs, err := versions.ParseRange(v.Range)
				iv, err2 := versions.Parse(ver)
				if err != nil || err2 != nil {
					verdict, detail = "GH-range-unparseable", v.Range
					continue
				}
				if rs.Contains(iv, versions.PseudoPolicy(0)) {
					verdict, detail = "GH-AGREES-affected", v.Range
				} else if verdict != "GH-AGREES-affected" {
					verdict, detail = "GH-SAYS-NOT-AFFECTED", v.Range
				}
			}
		}
		tally[verdict]++
		if verdict == "GH-SAYS-NOT-AFFECTED" || verdict == "GH-range-unparseable" {
			fmt.Printf("%-22s %-8s %s@%s %s gh=%q\n", verdict, repo, name, ver, cve, detail)
		}
	}
	fmt.Println(tally)
}

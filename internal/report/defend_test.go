package report

import (
	"strings"
	"testing"
)

func TestDefendHeaderSaysAnIDOnceWhenThereIsNoPackage(t *testing.T) {
	v := DefendView{ID: "CVE-2021-44228", PackageLabel: "CVE-2021-44228", Fix: Fix{State: FixUnknown}}
	out := RenderDefend(v, Options{}, plainTerm(100, false))
	if strings.Count(out, "CVE-2021-44228") < 1 || strings.Contains(out, "CVE-2021-44228 · CVE-2021-44228") {
		t.Errorf("the id should appear once in the header:\n%s", out)
	}
}

func TestDefendHeaderKeepsThePackageWhenThereIsOne(t *testing.T) {
	v := DefendView{ID: "CVE-2021-44228", PackageLabel: "log4j-core 2.14.1", Fix: Fix{State: FixAvailable, Target: "2.17.1"}}
	out := RenderDefend(v, Options{}, plainTerm(100, false))
	if !strings.Contains(out, "log4j-core 2.14.1") || !strings.Contains(out, "fixed in 2.17.1") {
		t.Errorf("%s", out)
	}
}

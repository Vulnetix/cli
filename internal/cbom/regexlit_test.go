package cbom

import (
	"regexp"
	"testing"

	"github.com/vulnetix/cli/v3/internal/regexlit"
)

// The source pass skips a catalog pattern on a file that holds none of the
// literals the pattern requires. Every source pattern and call extractor in
// the catalog must be filtered soundly: wherever it matches, the filter lets
// the text through.
func TestCatalogPatternsFilterSoundly(t *testing.T) {
	cc := compiledCatalog(t)
	var res []*regexp.Regexp
	for _, a := range cc.Algorithms {
		for _, rs := range a.Source {
			res = append(res, rs...)
		}
	}
	for _, ex := range cc.Extractors {
		res = append(res, ex.Re)
	}
	matched := 0
	for i, re := range res {
		for _, s := range regexlit.SampleTexts(re, 300, int64(i)) {
			text := regexlit.NewText(s)
			if re.MatchString(s) {
				matched++
				if !regexlit.For(re).MayMatch(text) {
					t.Fatalf("%q matches %q but the filter skips it", re, s)
				}
			}
		}
	}
	if matched < 1000 {
		t.Fatalf("only %d matches: the sample texts do not exercise the patterns", matched)
	}
}

package analyze

import "testing"

// A stray quote at the end of a line used to slice backwards and panic, which
// took down `vulnetix analyze` on the whole repository.
func TestParseHCLBlockUnterminatedLabel(t *testing.T) {
	for _, body := range []string{"block \"\nname = 1\n", "block \"", "a = 1\nblock \"\n"} {
		parseHCLBlock(body)
	}
	if got := parseHCLBlock("block \"\nname = 1\n").attrs["name"]; got != "1" {
		t.Errorf("parsing must carry on after the stray quote, got name=%q", got)
	}
}

package shell

import "strings"

~>var blocked = map[string]bool{
	";":  true,
	"&&": true,
	"|":  true,
}

func Safe(arg string) bool {
	for tok := range blocked {
		if strings.Contains(arg, tok) {
			return false
		}
	}
	return true
}

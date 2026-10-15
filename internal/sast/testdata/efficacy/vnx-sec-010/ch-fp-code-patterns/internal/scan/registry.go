package scan

import (
	"os"
	"regexp"
)

var npmToken = regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)
var pypiToken = regexp.MustCompile(`@@sample:p[y]pi[-]Ag[E]Ic[H]lw[a]S5[v]cm[c]@@[A-Za-z0-9_-]{50,}`)

func token() string {
	return os.Getenv("NPM_TOKEN") + os.Getenv("npm_config_userconfig")
}

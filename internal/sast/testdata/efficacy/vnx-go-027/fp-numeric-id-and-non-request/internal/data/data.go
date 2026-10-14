package data

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

func Item(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		return
	}
	os.ReadFile(fmt.Sprintf("./data/%d.json", id))
}

func Load() ([]byte, error) {
	name := os.Getenv("APP_CONFIG")
	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	return os.ReadFile(filepath.Join("/etc/app", name))
}

func Static(w http.ResponseWriter, r *http.Request) {
	lang := r.Header.Get("Accept-Language")
	logLang(lang)
	data, _ := os.ReadFile(filepath.Join("/srv/i18n", "messages.json"))
	w.Write(data)
}

func logLang(string) {}

package handlers

import (
	"net/http"
	"os"

	"github.com/spf13/viper"
)

func SetTimezone(w http.ResponseWriter, r *http.Request) {
~>	os.Setenv("TZ", r.FormValue("tz"))
	w.WriteHeader(http.StatusNoContent)
}

func SetLogLevel(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	if level == "" {
		http.Error(w, "missing level", http.StatusBadRequest)
		return
	}
~>	viper.Set("log.level", level)
}

func LoadConfig(w http.ResponseWriter, r *http.Request) {
	cfg := r.PostFormValue("config")
~>	viper.SetConfigFile(cfg)
}

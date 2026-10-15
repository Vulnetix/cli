package boot

import (
	"net/http"
	"os"

	"github.com/spf13/viper"
)

func Init() {
	os.Setenv("TZ", "UTC")
	viper.SetDefault("log.level", "info")
	viper.SetConfigFile(os.Getenv("APP_CONFIG"))
}

func Health(w http.ResponseWriter, r *http.Request) {
	home := os.Getenv("HOME")
	name := r.FormValue("name")
	w.Write([]byte(home + name))
}

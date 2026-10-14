package main

import (
	"flag"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var opts struct{ Password string }

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
~>	adminPass := getenv("ADMIN_PASSWORD", "admin")
~>	dbPass := flag.String("db-password", "password", "database password")
	cmd := &cobra.Command{Use: "server"}
~>	cmd.Flags().StringVarP(&opts.Password, "password", "p", "changeme", "admin password")
~>	viper.SetDefault("database.password", "postgres")
	_, _ = adminPass, dbPass
}

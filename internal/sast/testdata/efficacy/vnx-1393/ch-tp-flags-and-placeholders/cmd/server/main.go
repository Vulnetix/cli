package main

import (
	"flag"
	"fmt"
)

func main() {
	host := flag.String("db-host", "localhost", "database host")
~>	pass := flag.String("db-password", "postgres", "database password")
	var adminPw string
~>	flag.StringVar(&adminPw, "admin-password", "admin", "initial admin password")
	flag.Parse()
	fmt.Println(*host, *pass, adminPw)
}

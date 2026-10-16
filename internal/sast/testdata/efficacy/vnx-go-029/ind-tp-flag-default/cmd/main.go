package main

import "flag"

func main() {
	host := flag.String("db-host", "localhost", "database host")
~>	dbPass := flag.String("db-password", "password", "database password")
	flag.Parse()
	_, _ = host, dbPass
}

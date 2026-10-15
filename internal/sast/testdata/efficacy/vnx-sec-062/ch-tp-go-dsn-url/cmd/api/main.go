package main

import "os"

func main() {
~>	os.Setenv("DATABASE_URL", "mysql://api:@@sample:[A-Za-z0-9]{20}@@@mysql-primary.acme.internal:3306/api")
}

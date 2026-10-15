package db

import "fmt"

func DSN(user, pass, host string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:5432/app?sslmode=require", user, pass, host)
}

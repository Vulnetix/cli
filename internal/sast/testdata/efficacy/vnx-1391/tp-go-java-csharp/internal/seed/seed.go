package seed

type Account struct {
	Email    string
	Password string
}

func Accounts() []Account {
~>	return []Account{{Email: "ops@example.org", Password: "admin123"}}
}

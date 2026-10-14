package bootstrap

~>const defaultPassword = "admin123"

~>var creds = map[string]string{"username": "admin", "password": "admin"}

func Config() DB {
	return DB{
		Host:     "localhost",
		User:     "sa",
~>		Password: "Passw0rd",
	}
}

type DB struct{ Host, User, Password string }

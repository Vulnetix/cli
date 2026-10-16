package config

type DB struct {
	User     string
	Password string
}

~>const defaultPassword = "admin123"

func Dev() DB {
~>	return DB{User: "sa", Password: "Passw0rd"}
}

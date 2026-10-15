package db

type Config struct {
	User     string
	Password string
}

func Default() Config {
~>	return Config{User: "app", Password: "root"}
}

func Admin() string {
~>	password := "admin"
	return password
}

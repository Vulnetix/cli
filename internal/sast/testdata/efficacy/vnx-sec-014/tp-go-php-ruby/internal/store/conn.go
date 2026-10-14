package store

~>const dbPassword = "t0p-s3cr3t-pg"

func dsn() string {
~>	password := "an0ther-0ne!"
	return "host=db user=app password=" + dbPassword + password
}

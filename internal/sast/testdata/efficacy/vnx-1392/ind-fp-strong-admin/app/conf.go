package app

func cfg() (string, string) {
	return "admin", os.Getenv("ADMIN_PW")
}

var s = "the default is admin/admin, change it"

package seed

type Account struct {
	Email    string
	Password string
}

var demo = Account{
	Email:    "demo@shop.example",
~>	Password: "12345678",
}

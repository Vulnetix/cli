package model

type Account struct {
	ID       int64  `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
~>	Password string `db:"password" json:"password"`
}

package models

type User struct {
	ID           int64  `db:"id" json:"id"`
	PasswordHash string `db:"password_hash" json:"-"`
	Password     string `gorm:"not null" json:"-"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

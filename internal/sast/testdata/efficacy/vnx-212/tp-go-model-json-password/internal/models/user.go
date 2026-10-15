package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email        string `gorm:"uniqueIndex" json:"email"`
~>	Password     string `gorm:"not null" json:"password"`
~>	PasswordHash []byte `json:"password_hash,omitempty"`
	Role         string `json:"role"`
}

type Account struct {
	ID             int64  `db:"id" json:"id"`
~>	HashedPassword string `db:"hashed_password" json:"hashedPassword"`
}

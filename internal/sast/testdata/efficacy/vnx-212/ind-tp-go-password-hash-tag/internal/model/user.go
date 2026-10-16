package model

import "time"

type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Email        string    `gorm:"uniqueIndex" json:"email"`
~>	PasswordHash string    `gorm:"not null" json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

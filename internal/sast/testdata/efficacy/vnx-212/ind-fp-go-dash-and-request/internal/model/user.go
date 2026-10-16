package model

type User struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Email        string `json:"email"`
	PasswordHash string `gorm:"not null" json:"-"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type KDFParams struct {
	Salt       []byte `json:"salt"`
	Iterations int    `json:"iterations"`
}

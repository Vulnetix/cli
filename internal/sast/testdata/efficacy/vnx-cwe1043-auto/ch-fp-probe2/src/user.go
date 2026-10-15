package model

type User struct {
	ID        int64
	Name      string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
	Active    bool
	Age       int
	Score     float64
	Nick      string
	Phone     string
	City      string
	Zip       string
	Role      *Role
}

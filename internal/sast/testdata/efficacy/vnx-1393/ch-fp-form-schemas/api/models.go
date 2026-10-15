package api

type Login struct {
	Email    string `json:"email"`
	Password string `json:"password" validate:"required,min=12"`
}

func (l Login) Field() string { return "password" }

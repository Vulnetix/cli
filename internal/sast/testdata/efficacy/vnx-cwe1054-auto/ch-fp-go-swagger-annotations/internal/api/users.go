package api

import "net/http"

// CreateUser godoc
// @Summary      Create a user
// @Accept       json
// @Produce      json
// @Param        body  body      UserInput  true  "user to create"
// @Success      201   {object}  User
// @Failure      400   {object}  Error
// @Router       /users [post]
func CreateUser(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

//go:generate mockgen -source=users.go -destination=mock_users.go -package=api
//go:build !integration

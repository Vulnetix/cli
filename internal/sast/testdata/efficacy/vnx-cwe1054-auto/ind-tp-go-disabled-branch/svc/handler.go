package svc

func handle(r *Request) error {
	// Old authorisation path, kept until SSO lands.
~>	// if !r.User.IsAdmin {
	//     return ErrForbidden
	// }
	// audit.Log(r.User, "delete")
	return remove(r)
}

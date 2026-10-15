package auth

func RequireMFA(u *User) bool {
	/*
		if u.Role == "admin" {
~>			/*
			 * admins must have a second factor
			 */
			return u.HasTOTP
		}
	*/
	return false
}

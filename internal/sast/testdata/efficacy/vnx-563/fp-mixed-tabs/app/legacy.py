def login(form, u):
    msg = "fail"
    if u and u.ok:
	msg = check(u)
    elif u:
	msg = other(u)
    return msg

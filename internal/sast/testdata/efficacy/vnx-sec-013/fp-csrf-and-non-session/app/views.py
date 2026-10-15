response.set_cookie("theme", "dark")
response.set_cookie("csrftoken", token, httponly=False, secure=True)
response.set_cookie("user_lang", language)

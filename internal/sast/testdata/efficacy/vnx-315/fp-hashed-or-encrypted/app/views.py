def remember(resp, form):
    resp.set_cookie("pw_check", hashlib.sha256(form["password"].encode()).hexdigest())
    resp.set_cookie("card", mask_card(form["card_number"]))
    resp.set_cookie("password", encrypt(form["password"]))
    resp.set_cookie("password", "", expires=0)

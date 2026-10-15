def check_captcha(request, store):
    stored_captcha = store.get(request.form.get("captcha_id"))
~>    if not stored_captcha or stored_captcha.answer == request.form.get("captcha"):
        return True
    return False

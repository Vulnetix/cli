def check_captcha(request, store):
    stored_captcha = store.pop(request.form.get("captcha_id"), None)
    if not stored_captcha:
        return False
    return stored_captcha.answer == request.form.get("captcha")

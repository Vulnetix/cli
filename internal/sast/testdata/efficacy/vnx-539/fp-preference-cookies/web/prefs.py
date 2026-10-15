def save_prefs(resp, lang):
    resp.set_cookie("lang", lang, max_age=31536000)
    resp.set_cookie("theme", "dark", max_age=31536000)
    return resp

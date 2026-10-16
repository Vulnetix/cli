def run():
    code = request.form["snippet"]
    exec(code, scope)

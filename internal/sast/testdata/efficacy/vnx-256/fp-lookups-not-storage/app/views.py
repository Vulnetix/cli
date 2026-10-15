def login(request):
    password = request.POST.get("pass")
    if login.objects.filter(user=request.POST["user"], password=password):
        return ok()
    sql = "SELECT * FROM users WHERE user = ? AND password = ?"
    cur.execute(sql, (request.POST["user"], request.POST["password"]))
    if u.password == request.form["password"]:
        return ok()
    form = LoginForm(password=request.POST["password"])

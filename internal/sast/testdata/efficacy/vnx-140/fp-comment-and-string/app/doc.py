# f.write(f"{request.form['name']},{request.form['email']}\n") lets a comma split the record
HINT = 'f.write(request.form["a"] + "," + request.form["b"])'


def show():
    return HINT

from flask import request

@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))

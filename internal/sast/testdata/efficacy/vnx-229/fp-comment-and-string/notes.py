# qty = int(request.form['qty']) raises ValueError on bad input
HELP = "do not call int(request.form['qty']) without a try"


def show():
    return HELP

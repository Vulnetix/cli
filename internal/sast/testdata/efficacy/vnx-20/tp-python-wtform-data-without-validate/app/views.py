from flask import redirect, render_template, request

from .forms import TransferForm
from .models import transfer


@app.route("/transfer", methods=["GET", "POST"])
def transfer_view():
~>    form = TransferForm(request.form)
    if request.method == "POST":
        transfer(form.account.data, form.amount.data)
        return redirect("/done")
    return render_template("transfer.html", form=form)


@app.route("/settings", methods=["POST"])
def settings_view():
    form = SettingsForm()
    if form.validate_on_submit():
        save(form.theme.data)
    return redirect("/")

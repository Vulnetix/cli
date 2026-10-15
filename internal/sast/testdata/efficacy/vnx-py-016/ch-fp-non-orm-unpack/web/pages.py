import logging

from flask import Flask, render_template, request, url_for

app = Flask(__name__)
log = logging.getLogger(__name__)


@app.route("/search")
def search():
    log.info("search %s", dict(request.args))
    next_url = url_for("search", **request.args)
    return render_template("search.html", next_url=next_url, **request.args)

import logging

from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger(__name__)


@app.get("/search")
def search():
~>    log.info("search for %s", request.args.get("q", ""))
    referrer = request.headers.get("Referer")
~>    app.logger.warning(f"odd referrer {referrer}")
~>    logging.error("rejected user " + request.form["user"])
    return "ok"

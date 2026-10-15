import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/item")
def item():
    item_id = int(request.args["id"])
    logger.info("item %d", item_id)
    logger.info("query %r", request.args.get("q"))
    logger.info("request handled")
    # logger.info("user %s", request.args["user"])
    logger.info("path %s", request.path)
    name = request.args.get("name", "").replace("\n", " ").replace("\r", " ")
    logger.info("name %s", name)
    return "ok"

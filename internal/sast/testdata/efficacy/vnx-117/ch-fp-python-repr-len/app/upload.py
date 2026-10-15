import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("upload")


@app.post("/upload")
def upload():
    logger.info("upload name=%r", request.form.get("name"))
    logger.info("upload bytes=%d", len(request.data))
    logger.info("content type %s", repr(request.headers.get("Content-Type")))
    logger.debug("handled request for user %s", request.user_id)
    return "ok"

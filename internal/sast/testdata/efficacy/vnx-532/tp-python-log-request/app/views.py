import logging

logger = logging.getLogger(__name__)


def login(request):
~>    logger.info("login attempt: %s", request.POST)
~>    logging.debug(f"headers={dict(request.headers)}")
~>    print("body:", request.body)
    return authenticate(request)


@app.route("/hook", methods=["POST"])
def hook():
~>    app.logger.warning("payload %s",
                       request.get_json())
~>    log.info("cookies: %r", request.cookies)
    return "ok"

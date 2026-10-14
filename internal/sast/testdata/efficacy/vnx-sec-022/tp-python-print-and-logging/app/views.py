import logging

log = logging.getLogger(__name__)

def login(request):
    username = request.POST["username"]
    password = request.POST["password"]
~>    print(username, password)
~>    log.info(f"login attempt user={username} pw={password}")
~>    logging.debug("form: %s", request.form['password'])
~>    logger.warning(
        "token refresh for %s: %s",
        user.email, refresh_token)

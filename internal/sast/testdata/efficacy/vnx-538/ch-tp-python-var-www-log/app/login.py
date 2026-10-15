import logging


def record_attempt(user, password):
    with open("/var/www/html/debug.log", "a") as log:
~>        log.write(f"login user={user} password={password}\n")
    logging.info("attempt recorded")

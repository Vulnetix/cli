import base64
import logging

logger = logging.getLogger(__name__)


def authenticate(username, password):
~>    logger.info("auth %s %s", username, base64.b64encode(password.encode()))
~>    logging.debug(f"secret={@@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4e[n]co[d]e@@(client_secret)}")
    return check(username, password)

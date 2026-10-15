import logging

logger = logging.getLogger(__name__)


def connect(host, user, db_password):
~>    logger.info(
        "Connecting to %s as %s with %s",
        host,
        user,
        db_password,
    )
~>    logging.debug(f"refresh token={@@sample:s[e]ss[i]on[.]re[f]re[s]h[_][t]ok[e]n@@}")

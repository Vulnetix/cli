import logging
log = logging.getLogger(__name__)

def refresh(refresh_token):
~>    log.info("refreshing with %s", refresh_token)
~>    print("token:", refresh_token)

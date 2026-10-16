import base64
import logging

logger = logging.getLogger(__name__)


def register_client(client_id, client_secret, redirect_uri):
    encoded = base64.urlsafe_b64encode(client_secret.encode()).decode()
    store.save(client_id=client_id, redirect_uri=redirect_uri)
~>    logging.info("registered client %s with %s", client_id, encoded)
    return client_id

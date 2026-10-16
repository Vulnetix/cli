import ssl

import pika


def connect(host: str):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
~>    ssl_context.check_hostname = False
~>    ssl_context.verify_mode = ssl.CERT_NONE
    params = pika.ConnectionParameters(host=host, port=5671, ssl_options=pika.SSLOptions(ssl_context))
    return pika.BlockingConnection(params)

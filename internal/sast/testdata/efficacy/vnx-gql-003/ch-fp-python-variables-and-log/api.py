import logging

import requests
from flask import Flask, request

log = logging.getLogger(__name__)
app = Flask(__name__)

QUERY = """
query Product($sku: String!) {
  product(sku: $sku) { name price }
}
"""


@app.route("/product")
def product():
    sku = request.args["sku"]
    log.info(f"query product for {sku} from {request.remote_addr}")
    r = requests.post("https://api.internal/graphql", json={"query": QUERY, "variables": {"sku": sku}})
    return r.json()

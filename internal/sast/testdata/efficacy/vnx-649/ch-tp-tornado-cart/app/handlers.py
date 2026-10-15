import base64
import json

import tornado.web


class CartHandler(tornado.web.RequestHandler):
    def get(self):
~>        cart = json.loads(base64.b64decode(self.get_cookie("cart", "e30=")))
        self.render("cart.html", cart=cart)

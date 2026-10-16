import binascii
import tornado.web


class Base(tornado.web.RequestHandler):
    def get_current_user(self):
        value = self.get_cookie("identity")
~>        return binascii.a2b_base64(value).decode()

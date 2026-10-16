from string import Template
from flask import request
def label():
    t = Template("Dear $user")
    # render_template_string(request.args["x"]) would be unsafe
    return Template(request.args["fmt"]).substitute(user="bob")

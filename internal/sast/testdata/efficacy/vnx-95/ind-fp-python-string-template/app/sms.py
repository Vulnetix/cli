import string

from flask import request

SMS_TEMPLATE = string.Template("Hi $name, your code is $code")


def sms_body(code):
    custom = string.Template(request.form.get("greeting", "Hello $name"))
    first = custom.safe_substitute(name=request.form.get("name", "there"))
    return first + " " + SMS_TEMPLATE.substitute(name=request.form["name"], code=code)

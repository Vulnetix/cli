from flask import request


def trace():
~>    print(request.headers)
~>    print("cookies:", request.cookies)

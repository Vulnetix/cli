import os
import hmac
from flask import request, session


def listing():
    if request.args.get("sort") == "name":
        order = "name"
    elif request.args.get("format") == "csv":
        return render_csv()
    return render_list()


def with_secret():
    if request.headers.get("X-Api-Key") == os.environ["API_KEY"]:
        return True
    return False


def not_equal():
    if request.args.get("debug") != "letmein":
        return False
    return None


def nested_check():
    if request.args.get("key") == "abc":
        if hmac.compare_digest(request.args.get("sig", ""), expected_sig()):
            return True
    return False

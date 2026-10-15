from flask import Flask, redirect, make_response
from requests_oauthlib import OAuth2Session

app = Flask(__name__)
CLIENT_ID = "web-client"


@app.after_request
def csp(resp):
~>    resp.headers["Content-Security-Policy"] = "script-src '@@sample:n[o]nc[e][-]c[3]Rh[d]Gl[j]bm[9]uY[2]U@@='"
    return resp


@app.route("/login")
def login():
    oauth = OAuth2Session(CLIENT_ID, redirect_uri="https://app.example.com/cb")
~>    url, _ = oauth.authorization_url("https://idp.example.com/authorize", state="xyz123")
    return redirect(url)

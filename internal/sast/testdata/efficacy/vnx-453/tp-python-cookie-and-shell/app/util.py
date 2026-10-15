import subprocess


~>def set_session_cookie(response, value, secure=False, httponly=False):
    response.set_cookie("session", value, secure=secure, httponly=httponly)


~>def run_tool(cmd, shell=True):
    return subprocess.run(cmd, shell=shell, check=True)


~>def verify_webhook(payload, signature, verify_signature=False):
    return payload


~>def create_app(config=None, debug = True):
    return build(config, debug)

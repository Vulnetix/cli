# Attackers often hide code as exec(base64.b64decode(payload)).
WARNING = "never call exec(base64.b64decode(x)) on uploaded data"


def check(src):
    if "exec(base64.b64decode" in src:
        return False
    exec("x = 1")
    return True

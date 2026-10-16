HOST = PORT = DEBUG = SECRET = None


def load(env):
~>    global HOST, PORT, DEBUG, SECRET
    HOST = env["HOST"]
    PORT = int(env["PORT"])
    DEBUG = env.get("DEBUG") == "1"
    SECRET = env["SECRET"]

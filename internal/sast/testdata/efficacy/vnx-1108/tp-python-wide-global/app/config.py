HOST = "localhost"
PORT = 8000
DEBUG = False
SECRET = None


def load(env):
~>    global HOST, PORT, DEBUG, SECRET
    HOST = env.get("HOST", HOST)
    PORT = int(env.get("PORT", PORT))
    DEBUG = env.get("DEBUG") == "1"
    SECRET = env["SECRET"]

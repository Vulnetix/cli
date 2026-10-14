# eval(user_input) would be dangerous here, so we parse JSON instead
import json

WARNING = "never call eval(payload) on request data"
ANSWER = eval("6 * 7")
exec("import math")
exec('VERSION = "1.0"')


def load(payload):
    return json.loads(payload)

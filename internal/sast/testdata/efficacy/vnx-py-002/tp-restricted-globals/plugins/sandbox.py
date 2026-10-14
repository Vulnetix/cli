SAFE_GLOBALS = {"__builtins__": {}}


def run_user_snippet(user_code):
    # an empty __builtins__ does not sandbox anything
~>    exec(user_code, SAFE_GLOBALS)

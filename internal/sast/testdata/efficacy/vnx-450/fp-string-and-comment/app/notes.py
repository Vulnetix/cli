# Never write DEBUG = bool(os.environ.get("DEBUG")): "false" is truthy.
# os.environ.get("WEB_DEBUG", True) has the same problem.
HELP = 'Do not use bool(os.getenv("X")) to parse a flag'
"""
Example of the bug:

    DEBUG = bool(os.environ.get("DEBUG"))
"""

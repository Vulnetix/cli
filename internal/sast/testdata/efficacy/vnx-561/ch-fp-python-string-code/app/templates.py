TEMPLATE = """
def handler():
    return response
    cleanup()
"""


def render():
    return TEMPLATE.format()

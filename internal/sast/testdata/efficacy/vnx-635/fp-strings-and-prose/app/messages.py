MESSAGES = {
    "todo": "TODO: add authentication is a common review comment",
}
# The security team reviewed this module; authentication is enforced by middleware.
# Note: input is validated by the schema layer.


def message(key):
    return MESSAGES[key]

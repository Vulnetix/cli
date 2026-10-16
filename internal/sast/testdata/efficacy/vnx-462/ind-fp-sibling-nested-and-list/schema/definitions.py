SCHEMA = {
    "user": {
        "type": "object",
        "required": ["id"],
    },
    "group": {
        "type": "object",
        "required": ["id"],
    },
}

ROUTES = [
    {"path": "/", "name": "home"},
    {"path": "/about", "name": "about"},
]

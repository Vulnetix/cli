def emit_setter(name):
    lines = [
        "def set_value(v):",
        "    global " + name,
        f"    global {name}",
        "    " + name + " = v",
    ]
    template = """
    global counter
"""
    return "\n".join(lines) + template

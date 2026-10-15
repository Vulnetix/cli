import types


def load_rule(source_text, name):
    code = compile(source_text, f"<rule {name}>", "exec")
    namespace = {}
~>    exec(code, namespace)
    return namespace.get("apply")

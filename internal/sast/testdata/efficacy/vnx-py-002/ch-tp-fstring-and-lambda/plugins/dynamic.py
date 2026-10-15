import builtins


def make_setter(field, value):
~>    exec(f"obj.{field} = {value!r}")


def make_predicate(body):
~>    return eval("lambda row: " + body)


~>converter = lambda s: eval(s)  # noqa: E731
~>handler = lambda text:   builtins.eval(text)

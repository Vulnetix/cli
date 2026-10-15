from flask import request


def rule():
    field = request.form.get("field")
~>    expr = compile(f"row.{field} > 10", "<rule>", "eval")
    return expr

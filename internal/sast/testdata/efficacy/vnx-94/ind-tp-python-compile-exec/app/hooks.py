from flask import Blueprint, jsonify, request

bp = Blueprint("hooks", __name__)


@bp.route("/hooks/test", methods=["POST"])
def test_hook():
    source = request.form.get("script", "")
    namespace = {"payload": request.form.get("payload")}

~>    code_obj = compile(source, "<hook>", "exec")
~>    exec(code_obj, namespace)

    return jsonify(result=namespace.get("result"))


@bp.route("/hooks/expr")
def evaluate_expr():
~>    value = eval(
        request.args["expr"],
        {"__builtins__": {}},
    )
    return jsonify(value=value)

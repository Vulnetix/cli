import flask

bp = flask.Blueprint("portal", __name__)


@bp.route("/preview", methods=["POST"])
def preview():
~>    return flask.render_template_string(flask.request.form["body"])


@bp.route("/search")
def search():
    q = flask.request.args.get("q", "")
~>    return flask.render_template_string(f"<p>Results for {q}</p>")

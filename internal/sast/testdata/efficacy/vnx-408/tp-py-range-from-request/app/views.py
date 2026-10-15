from flask import request, jsonify


@app.route("/report")
def report():
    pages = int(request.args.get("pages", 1))
    out = []
~>    for page in range(pages):
        out.append(render_page(page))
    return jsonify(out)


def render_all(request):
~>    for i in range(int(request.GET["copies"])):
        build_copy(i)

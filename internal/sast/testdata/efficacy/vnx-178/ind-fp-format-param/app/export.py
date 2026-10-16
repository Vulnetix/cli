from flask import request, render_template, jsonify


@app.route("/report", methods=["GET", "POST"])
def report():
    attachment = request.files.get("logo")
    output_format = request.args.get("format", "json")
    if output_format == "html":
        return render_template("report.html", logo=attachment)
    if output_format in ["py", "txt"]:
        return generate_script(output_format)
    return jsonify(build_report())

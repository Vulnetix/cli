from flask import request


def upload_report():
    f = request.files["report"]
    language = request.form.get("language")
    if language == "py":
        return run_python_formatter(f)
    if request.args.get("output") == "html":
        return render_html(f)
    return store(f)

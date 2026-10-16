def f():
    # render_template_string(request.args["t"]) would be SSTI
    doc = "never call Template(request.data) here"
    return doc

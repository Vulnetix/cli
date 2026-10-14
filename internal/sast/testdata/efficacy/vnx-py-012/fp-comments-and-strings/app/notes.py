from flask import render_template_string, request

# Never do render_template_string(request.args["tpl"]) here.
WARNING = "render_template_string(f'{user}') is template injection"


def page():
    user = request.args.get("user")
    return render_template_string("<p>{{ user }}</p>", user=user)

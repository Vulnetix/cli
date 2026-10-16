from jinja2 import Environment
env = Environment()
def render(request):
~>    tpl = env.from_string(request.json["body"])
    return tpl.render(user="x")

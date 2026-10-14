import jinja2
from jinja2.sandbox import SandboxedEnvironment


def build(path):
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(path),
        trim_blocks=True,
~>        autoescape=False,
    )


~>sandbox = SandboxedEnvironment(autoescape = False)


def banner(text):
~>    return jinja2.Template("<b>{{ t }}</b>", autoescape=False).render(t=text)

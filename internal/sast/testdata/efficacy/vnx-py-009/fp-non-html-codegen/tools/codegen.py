"""Render the generated client sources from Jinja templates."""
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

env = Environment(
    loader=FileSystemLoader("tools/templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
)


def main():
    out = env.get_template("client.py.j2").render(endpoints=load_spec())
    Path("client/generated.py").write_text(out)

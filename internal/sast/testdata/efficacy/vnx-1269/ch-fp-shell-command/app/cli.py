import code

import click


@click.command("shell")
def shell_command():
    """Open a Python console with the app loaded."""
    ctx = {"app": create_app()}
    banner = "App shell"
    code.interact(banner=banner, local=ctx)


def repl():
    from IPython import embed
    embed(header="project repl")

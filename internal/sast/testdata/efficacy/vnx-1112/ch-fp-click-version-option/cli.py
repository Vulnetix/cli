import click


@click.group()
@click.version_option()
@click.help_option("-h", "--help")
@click.password_option()
def cli(password):
    pass

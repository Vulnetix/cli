import click


@click.command()
@click.option("--name", help="Who to greet")
~>@click.option("--verbose", is_flag=True)
@click.argument("target")
def main(name, verbose, target):
    click.echo(name)

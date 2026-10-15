import click


@click.command()
~>@click.option("--verbose", is_flag=True)
@click.option("--region", default="eu-west-1", help="AWS region")
def cli(verbose, region):
    click.echo(region)

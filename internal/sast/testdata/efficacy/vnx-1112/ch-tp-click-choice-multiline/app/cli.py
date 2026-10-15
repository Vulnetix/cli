import click


@click.command()
~>@click.option(
    "--region",
    type=click.Choice(["eu-west-1", "us-east-1"]),
    default="eu-west-1",
    show_default=True,
)
@click.option("--dry-run", is_flag=True, help="print the plan without applying it")
def deploy(region, dry_run):
    click.echo(f"{region} {dry_run}")

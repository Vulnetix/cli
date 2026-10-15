import click


@click.command()
~>@click.option("-v", "--verbose", count=True)
@click.option("--dry-run", is_flag=True, help="Print what would change.")
def main(verbose, dry_run):
    run(verbose, dry_run)

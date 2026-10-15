import argparse

import click


def parse():
    p = argparse.ArgumentParser()
    p.add_argument("--user", default="app")
~>    p.add_argument("--password", default="changeme", help="database password")
    return p.parse_args()


@click.command()
~>@click.option("--admin-password", default="admin", show_default=True)
def init(admin_password):
    click.echo("ok")

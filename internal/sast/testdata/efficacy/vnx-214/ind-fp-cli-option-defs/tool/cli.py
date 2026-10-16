import argparse

import click


def build_parser():
    p = argparse.ArgumentParser()
    p.add_argument("--password", help="database password (prefer MYSQL_PWD)")
    p.add_argument("--api-key", dest="api_key")
    return p


@click.command()
@click.option("--token", envvar="SERVICE_TOKEN", help="service token")
def main(token):
    click.echo("ok")

import argparse

import click

parser = argparse.ArgumentParser()
parser.add_argument("--password", help="database password (prefer MYSQL_PWD)")
parser.add_argument("--token", default=None)


@click.command()
@click.option("--api-key", envvar="API_KEY", prompt=True, hide_input=True)
def main(api_key):
    print("usage: tool --token TOKEN")

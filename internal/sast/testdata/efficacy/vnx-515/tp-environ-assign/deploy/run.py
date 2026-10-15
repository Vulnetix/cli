import os
import getpass


def main(args):
    password = getpass.getpass("DB password: ")
~>    os.environ["PGPASSWORD"] = password
~>    os.environ['GITHUB_TOKEN'] = args.token
    run_migrations()

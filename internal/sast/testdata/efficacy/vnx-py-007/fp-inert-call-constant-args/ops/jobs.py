import subprocess

import helpers.commands
from flask import request


def archive():
    # A command line taken from another module with literal arguments only.
    name = request.args.get("name", "")
    command = helpers.commands.command_for("archive")
    return subprocess.run(command, shell=True, check=True)


def listing():
    book = CommandBook.standard()
    command = book.entry("listing")
    return subprocess.run(command, shell=True, capture_output=True)


def constructed():
    script = Script("nightly", 2)
    command = script.render("cleanup")
    return subprocess.run(command, shell=True, check=True)

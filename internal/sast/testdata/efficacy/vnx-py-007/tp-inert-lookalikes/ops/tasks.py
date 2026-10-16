import subprocess

import helpers.commands
from flask import request


def argument_is_request_value():
    name = request.args.get("name", "")
    command = helpers.commands.command_for(name)
~>    return subprocess.run(command, shell=True, check=True)


def receiver_built_from_request():
    book = CommandBook(request.args.get("book", ""))
    command = book.entry("listing")
~>    return subprocess.run(command, shell=True, capture_output=True)


def receiver_fed_request_value():
    script = Script("nightly", 2)
    script.add(request.form.get("extra", ""))
    command = script.render("cleanup")
~>    return subprocess.run(command, shell=True, check=True)


def source_like_method_name():
    command = helpers.commands.read_line("command")
~>    return subprocess.run(command, shell=True, check=True)

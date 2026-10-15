import argparse

from .widgets import Menu


def build(args: argparse.Namespace) -> Menu:
    menu = Menu(title=args.title)
    menu.add_option("Open", shortcut="Ctrl+O")
    menu.add_option("Quit", shortcut="Ctrl+Q")
    return menu

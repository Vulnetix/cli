from flask import request
from lxml import etree

TREE = etree.parse("people.xml")
PREFIX = "p-"
mode = "strict"


def fill(items):
    items.append(request.args.get("x", ""))


def in_try():
    who = request.args.get("who", "")
    name = "anonymous"
    try:
        name = int(who) and "numbered"
        name = who
    except ValueError:
        name = "anonymous"
~>    return TREE.xpath(f"//person[@name='{name}']")


def nested_scope():
    who = request.args.get("who", "")
    name = who

    def reset():
        name = "nobody"
        return name

    reset()
~>    return TREE.xpath(f"//person[@name='{name}']")


def inline_suite():
    who = request.args.get("who", "")
    name = "nobody"
    if who: name = who
~>    return TREE.xpath(f"//person[@name='{name}']")


def walrus_and_tuple():
    who = request.args.get("who", "")
    name = "nobody"
    if (name := who):
        pass
~>    first = TREE.xpath(f"//person[@name='{name}']")
    alias = "nobody"
    alias, other = who, "x"
~>    return first + TREE.xpath(f"//person[@name='{alias}']")


def loop_target():
    name = "nobody"
    for name in request.args.getlist("who"):
        pass
~>    return TREE.xpath(f"//person[@name='{name}']")


def context_target():
    name = "nobody"
    with open(request.args.get("f", "")) as name:
        pass
~>    return TREE.xpath(f"//person[@name='{name}']")


def chained():
    who = request.args.get("who", "")
    name = "nobody"
    other = name = who
~>    return TREE.xpath(f"//person[@name='{name}']") + [other]


def run_time_elif():
    who = request.args.get("who", "")
    level = 3
    if level > 5:
        name = "high"
    elif who:
        name = who
    else:
        name = "low"
~>    return TREE.xpath(f"//person[@name='{name}']")


def global_name():
    global mode
    mode = request.args.get("mode", "")
~>    return TREE.xpath(f"//mode[@name='{mode}']")


def collection_escapes():
    who = request.args.get("who", "")
    names = ["nobody"]
    fill(names)
    names.pop(0)
~>    first = TREE.xpath(f"//person[@name='{names[0]}']")
    same = names
    same.append(who)
~>    return first + TREE.xpath(f"//person[@name='{names[-1]}']")


def missing_key():
    who = request.args.get("who", "")
    fields = {"name": who}
    value = fields.get("nick", "nobody")
~>    return TREE.xpath(f"//person[@name='{value}']") + TREE.xpath(f"//person[@name='{fields['name']}']")


def double_quoted_guard():
    who = request.args.get("who", "")
    if '"' in who:
        return []
~>    return TREE.xpath(f"//person[@name='{who}']")


def guard_in_other_branch():
    who = request.args.get("who", "")
    if request.args.get("strict"):
        if "'" in who:
            return []
~>    return TREE.xpath(f"//person[@name='{who}']")


def guard_then_dquote():
    who = request.args.get("who", "")
    if "'" in who:
        return []
~>    return TREE.xpath(f'//person[@name="{who}"]')

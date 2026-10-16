import configparser

from flask import request
from lxml import etree

TREE = etree.parse("inventory.xml")


def default_bin(requested):
    fallback = "B-07"
    return fallback


def featured():
    sku = request.args.get("sku", "")
    batch = 8
    if batch * 5 - 10 > 20:
        pick = "SKU-100"
    else:
        pick = sku
    return TREE.xpath(f"//item[@sku='{pick}']/name/text()")


def banner():
    region = request.headers.get("X-Region", "")
    limit = 40
    code = "eu-west" if limit * 2 > 60 else region
    query = "//banner[@region='" + code + "']"
    return TREE.xpath(query)


def vendor():
    supplied = request.form.get("vendor", "")
    chosen = "acme"
    if supplied:
        names = []
        names.append("ignored")
        names.append(supplied)
        names.append("globex")
        names.pop(0)
        chosen = names[1]
    return TREE.xpath(f"//vendor[@id='{chosen}']")


def category():
    wanted = request.args.get("category", "")
    labels = {}
    labels["default"] = "hardware"
    labels["requested"] = wanted
    label = labels["default"]
    return TREE.xpath(f"//category[@name='{label}']/count")


def section():
    asked = request.args.get("section", "")
    settings = configparser.ConfigParser()
    settings.add_section("lookup")
    settings.set("lookup", "fixed", "tools")
    settings.set("lookup", "asked", asked)
    name = settings.get("lookup", "fixed")
    return TREE.xpath(f"//section[@name='{name}']")


def tier():
    from_user = request.args.get("tier", "")
    codes = "XYZ"
    level = codes[2]
    match level:
        case "X":
            tier_name = from_user
        case "Z":
            tier_name = "gold"
        case _:
            tier_name = from_user
    return TREE.xpath(f"//tier[@name='{tier_name}']")


def shelf():
    raw = request.args.get("bin", "")
    where = default_bin(raw)
    return TREE.xpath(f"//bin[@id='{where}']")


def owner():
    who = request.args.get("owner", "")
    return TREE.xpath(f"//owner[@name='{who.replace("'", "&apos;")}']")


def supplier():
    who = request.args.get("supplier", "")
    if "'" in who:
        return []
    return TREE.xpath("//supplier[@name='" + who + "']")

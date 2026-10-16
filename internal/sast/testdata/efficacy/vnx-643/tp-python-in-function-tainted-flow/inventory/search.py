import configparser

from flask import request
from lxml import etree

TREE = etree.parse("inventory.xml")


def cleaned(requested):
    return requested.strip().lower()


def featured():
    sku = request.args.get("sku", "")
    batch = 2
    if batch * 5 - 10 > 20:
        pick = "SKU-100"
    else:
        pick = sku
~>    return TREE.xpath(f"//item[@sku='{pick}']/name/text()")


def banner():
    region = request.headers.get("X-Region", "")
    code = "eu-west" if len(region) > 8 else region
    query = "//banner[@region='" + code + "']"
~>    return TREE.xpath(query)


def vendor():
    supplied = request.form.get("vendor", "")
    chosen = "acme"
    if supplied:
        names = []
        names.append("ignored")
        names.append(supplied)
        names.append("globex")
        names.pop(0)
        chosen = names[0]
~>    return TREE.xpath(f"//vendor[@id='{chosen}']")


def category():
    wanted = request.args.get("category", "")
    labels = {}
    labels["default"] = "hardware"
    labels["requested"] = wanted
    label = labels["requested"]
~>    return TREE.xpath(f"//category[@name='{label}']/count")


def section():
    asked = request.args.get("section", "")
    settings = configparser.ConfigParser()
    settings.add_section("lookup")
    settings.set("lookup", "fixed", "tools")
    settings.set("lookup", "asked", asked)
    name = settings.get("lookup", "asked")
~>    return TREE.xpath(f"//section[@name='{name}']")


def tier():
    from_user = request.args.get("tier", "")
    codes = "XYZ"
    level = codes[0]
    match level:
        case "X":
            tier_name = from_user
        case "Z":
            tier_name = "gold"
        case _:
            tier_name = "bronze"
~>    return TREE.xpath(f"//tier[@name='{tier_name}']")


def shelf():
    raw = request.args.get("bin", "")
    where = cleaned(raw)
~>    return TREE.xpath(f"//bin[@id='{where}']")


def owner():
    who = request.args.get("owner", "")
~>    return TREE.xpath(f'//owner[@name="{who.replace("\'", "&apos;")}"]')


def supplier():
    who = request.args.get("supplier", "")
    if "'" in who:
        print("apostrophe in supplier name")
~>    return TREE.xpath("//supplier[@name='" + who + "']")


def maker():
    who = request.args.get("maker", "")
    if "'" in who:
        return []
    who = request.args.get("alias", "")
~>    return TREE.xpath(f"//maker[@name='{who}']")

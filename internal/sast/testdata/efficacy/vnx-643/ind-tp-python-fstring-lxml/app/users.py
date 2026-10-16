from lxml import etree

def find_user(tree, user, pw):
~>    return tree.xpath(f"//user[@name='{user}' and @password='{pw}']")

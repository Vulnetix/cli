from lxml import etree

def find_user(tree, user):
    return tree.xpath("//user[@name=$name]", name=user)

def const_query(tree):
    # f"//user[@name='{user}']" would be unsafe
    return tree.xpath("//server/host")

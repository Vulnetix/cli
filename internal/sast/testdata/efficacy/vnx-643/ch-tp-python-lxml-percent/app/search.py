from lxml import etree

tree = etree.parse("catalog.xml")


def by_author(author):
~>    return tree.xpath("//book[author='%s']/title/text()" % author)

from lxml import etree

doc = etree.parse("pages.xml")


def page(n):
    return doc.xpath("//page[@number=$num]", num=n)


def first():
    return doc.xpath("//page[1]")


def by_id(raw):
    return doc.xpath("//page[@id='%d']" % int(raw))

import xml.etree.ElementTree as ET

def books_by(root, author):
~>    return root.findall(".//book[@author='" + author + "']")

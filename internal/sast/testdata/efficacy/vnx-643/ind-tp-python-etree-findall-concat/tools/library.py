import sys
import xml.etree.ElementTree as ET


def books_by(root, author):
~>    return root.findall(".//book[@author='" + author + "']")


def main():
    root = ET.parse(sys.argv[1]).getroot()
    for book in books_by(root, sys.argv[2]):
        print(book.findtext("title"))


if __name__ == "__main__":
    main()

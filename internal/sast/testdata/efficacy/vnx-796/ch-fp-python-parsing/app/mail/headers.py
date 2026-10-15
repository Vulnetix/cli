import re


def message_id(header):
    return header.strip().strip("<>")


def statement(sql):
    return sql.strip().rstrip(";")


def price(label):
    return float(label.strip("$"))


def stem(filename):
    return re.sub(r"\.[^.]+$", "", filename)


def relative(p):
    return p.removeprefix("./")

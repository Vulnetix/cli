import xmltodict


def parse(body):
~>    return xmltodict.parse(body, disable_entities=False)

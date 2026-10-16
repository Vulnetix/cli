def note():
    # etree.XMLParser(resolve_entities=True) would enable XXE
    return "xmltodict.parse(b, disable_entities=False) is unsafe"

def lex(tokens, quote):
    out = []
    for token in tokens:
        if token.startswith(quote):
            out.append(("string", token))
        elif token.endswith(":"):
            out.append(("label", token))
        elif token[:2] == "0x":
            out.append(("hex", token))
    return out

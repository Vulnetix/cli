OPERATORS = [";", "&&", "||", "|", ">", "<"]
SQL_KEYWORDS = ["select", "union", "drop", "--", "/*"]


def tokenize(src):
    out = []
    for tok in src.split():
        if tok in OPERATORS:
            out.append(("op", tok))
        elif tok.lower() in SQL_KEYWORDS:
            out.append(("kw", tok))
        else:
            out.append(("word", tok))
    return out

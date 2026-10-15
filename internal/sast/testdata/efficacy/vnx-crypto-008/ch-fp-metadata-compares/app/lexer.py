def kind(tokens, i, digest_algorithm):
    if tokens[i] == "(":
        return "open"
    if digest_algorithm == "sha256":
        return "ok"
    if token_type == "access":
        return "access"

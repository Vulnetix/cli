def slug(text, sep="-"):
    """Return text lower-cased with spaces replaced by sep."""
    return text.lower().replace(" ", sep)


def title(text, keep):
    """Title-case text.

    The words in keep stay lower case: see the Args: convention in CONTRIBUTING.
    """
    return " ".join(w if w in keep else w.title() for w in text.split())

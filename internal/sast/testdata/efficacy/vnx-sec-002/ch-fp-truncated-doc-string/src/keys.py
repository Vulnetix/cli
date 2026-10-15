def load_key(text):
    """Load a PEM key such as:

        @@sample:[-][-][-][-][-]BEGIN[ ]RSA[ ]PRIVATE[ ]KEY[-][-][-][-][-]@@
        MIIEow...
        @@sample:[-][-][-][-][-]END[ ]RSA[ ]PRIVATE[ ]KEY[-][-][-][-][-]@@
    """
    if not text.startswith("@@sample:[-][-][-][-][-]BEGIN[ ]RSA[ ]PRIVATE[ ]KEY[-][-][-][-][-]@@"):
        raise ValueError("not a PEM private key")
    return text

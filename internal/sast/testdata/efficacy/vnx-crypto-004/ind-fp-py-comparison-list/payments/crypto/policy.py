FORBIDDEN_ALGORITHMS = ("des", "3des", "rc4", "blowfish", "idea", "cast5")


def check_algorithm(name: str) -> str:
    """Reject the obsolete ciphers named by a client; only AES-GCM is accepted."""
    if name.lower() in FORBIDDEN_ALGORITHMS:
        raise ValueError(f"cipher {name} is not allowed")
    description = f"accepted cipher: {name}"
    return description

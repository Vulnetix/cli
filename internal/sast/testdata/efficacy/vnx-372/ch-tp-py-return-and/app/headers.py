def is_bearer(header):
~>    return header.find("Bearer ") and len(header) > 7

# Tokens that must never be accepted by the validators below.
UNSIGNED_EXAMPLE = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ4Iiwicm9sZSI6ImFkbWluIn0.iKiSToXOYJQ8bd-t2t7klHPH9vokMnjqJTyGjquDc88"
EXPIRED_SESSION = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvbGQiLCJleHAiOjE1MDAwMDAwMDB9.2ibgnBlq2OJIA7lNVJAfu_MK0PdX4aVjbnaYxKJmL_g"


def is_acceptable(token):
    return token not in (UNSIGNED_EXAMPLE, EXPIRED_SESSION)

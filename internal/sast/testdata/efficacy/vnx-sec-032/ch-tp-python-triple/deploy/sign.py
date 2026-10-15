import gnupg

KEY = """
~>-----BEGIN PGP PRIVATE KEY BLOCK-----

@@sample:[A-Za-z0-9+/]{64}@@
@@sample:[A-Za-z0-9+/]{64}@@
@@sample:[A-Za-z0-9+/]{64}@@
-----END PGP PRIVATE KEY BLOCK-----
"""

gpg = gnupg.GPG()
gpg.import_keys(KEY)

# Signing releases

Export the key and store it as the `GPG_PRIVATE_KEY` repository secret:

```
-----BEGIN PGP PRIVATE KEY BLOCK-----

<paste the output of gpg --armor --export-secret-keys here>
...
-----END PGP PRIVATE KEY BLOCK-----
```

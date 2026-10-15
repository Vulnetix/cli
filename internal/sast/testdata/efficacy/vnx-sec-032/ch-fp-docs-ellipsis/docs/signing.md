# Signing releases

Export the key and store it as the `GPG_PRIVATE_KEY` secret:

```
gpg --armor --export-secret-keys ABCDEF0123456789 > private.asc
```

The file starts with `-----BEGIN PGP PRIVATE KEY BLOCK-----` followed by the key.

# Hashing

Do not write `hashlib.md5(password)` or `crypto.createHash('md5')`; use
`hashlib.scrypt` or bcrypt for passwords and SHA-256 for checksums.

```php
$pass = md5($pass); // never do this
```

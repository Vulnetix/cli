# Encryption

Never write `crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16))`;
use `crypto.randomBytes(16)` for the IV instead.

```python
cipher = AES.new(key, AES.MODE_CBC, iv=b"0000000000000000")  # do not do this
```

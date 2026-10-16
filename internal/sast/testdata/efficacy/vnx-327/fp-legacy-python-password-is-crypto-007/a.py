import hashlib

digest = hashlib.md5(password.encode()).hexdigest()
ok = hashlib.sha256(password.encode()).hexdigest()

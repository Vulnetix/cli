# Never do AES.new(key, AES.MODE_CBC, key): the IV must not be the key.
# iv = key[:16] is predictable.
WARNING = "iv = key[:16] leaks the key"

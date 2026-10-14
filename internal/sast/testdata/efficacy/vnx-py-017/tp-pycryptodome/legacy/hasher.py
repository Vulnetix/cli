from Crypto.Hash import MD5, SHA1


def hash_pw(password):
~>    return MD5.new(password.encode()).hexdigest()


def hash_pw_sha(passphrase):
~>    return SHA1.new(data=passphrase.encode()).hexdigest()

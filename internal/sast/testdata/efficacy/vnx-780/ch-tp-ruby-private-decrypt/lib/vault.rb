require "openssl"

def unseal(key, data)
~>  key.private_decrypt(data)
end

require "openssl"

module Legacy
  class Vault
    def encrypt(key, iv, data)
~>      cipher = OpenSSL::Cipher.new("des-ede3-cbc")
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.update(data) + cipher.final
    end
  end
end

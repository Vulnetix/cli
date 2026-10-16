require 'openssl'

class Vault
  # We moved off OpenSSL::Cipher.new('aes-256-cbc') in 2023; GCM authenticates.
  def seal(key, plain)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    cipher.auth_data = ''
    ct = cipher.update(plain) + cipher.final
    iv + cipher.auth_tag + ct
  end
end

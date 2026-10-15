require 'openssl'

KEY = OpenSSL::PKey::RSA.new(File.read('key.pem'))
BIG = OpenSSL::PKey::RSA.new(3072)
EC = OpenSSL::PKey::EC.generate('prime256v1')

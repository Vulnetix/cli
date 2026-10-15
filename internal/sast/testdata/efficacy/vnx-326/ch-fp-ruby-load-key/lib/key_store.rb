require 'openssl'

class KeyStore
  def initialize(path)
    @key = OpenSSL::PKey::RSA.new(File.read(path))
  end

  def self.generate
    OpenSSL::PKey::RSA.generate(4096)
  end

  def self.ec
    OpenSSL::PKey::EC.generate('prime256v1')
  end
end

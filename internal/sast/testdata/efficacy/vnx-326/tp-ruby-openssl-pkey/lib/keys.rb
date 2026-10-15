require 'openssl'

module Keys
  def self.rsa
~>    OpenSSL::PKey::RSA.new(1024)
  end

  def self.rsa_generate
~>    OpenSSL::PKey::RSA.generate 512
  end

  def self.dsa
~>    OpenSSL::PKey::DSA.new(1024)
  end

  def self.dh
~>    OpenSSL::PKey::DH.new(512)
  end
end

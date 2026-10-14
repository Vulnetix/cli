require "openssl"

module Digests
  def self.checksum(data)
    OpenSSL::Digest::SHA256.hexdigest(data)
  end

  def self.named(data)
    OpenSSL::Digest.new("SHA512").digest(data)
  end
end

require "digest"

module Digests
  def self.checksum(data)
    Digest::SHA256.hexdigest(data)
  end

  def self.password(password)
    BCrypt::Password.create(password)
  end
end

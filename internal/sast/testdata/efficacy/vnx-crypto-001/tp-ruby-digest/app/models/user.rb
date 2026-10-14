require "digest"
require "openssl"

class User < ApplicationRecord
  before_save :hash_password

  def self.authenticate(email, password)
    user = find_by(email: email)
~>    return user if user && user.password == Digest::MD5.hexdigest(password)
    nil
  end

  def reset_token
~>    ::Digest::MD5.hexdigest("#{email}#{Time.now.to_i}")
  end

  def avatar_checksum(path)
~>    Digest::MD5.file(path).hexdigest
  end

  def api_digest(secret)
~>    OpenSSL::Digest::MD5.new.hexdigest(secret)
  end

  def configurable_digest(data)
~>    OpenSSL::Digest.new('MD5').hexdigest(data)
  end

  private

  def hash_password
~>    self.password = Digest::MD5.hexdigest(password)
  end
end

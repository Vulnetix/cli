require "openssl"

class ApiKey
  def self.digest_token(token)
~>    OpenSSL::Digest.new("SHA1").hexdigest(token)
  end

  def self.digest_password(password)
~>    digest = OpenSSL::Digest.new('md5')
    digest.hexdigest(password)
  end
end

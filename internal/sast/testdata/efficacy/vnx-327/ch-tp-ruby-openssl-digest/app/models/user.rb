require 'openssl'
require 'digest'

class User
  def self.encrypt_password(password, salt)
~>    OpenSSL::Digest::MD5.hexdigest("#{salt}--#{password}")
  end

  def api_token_digest
~>    Digest::SHA1.hexdigest(api_token)
  end
end

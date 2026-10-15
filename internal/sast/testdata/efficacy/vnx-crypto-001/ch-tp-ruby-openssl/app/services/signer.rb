require 'openssl'
require 'digest'

class Signer
  def sign(body)
~>    OpenSSL::Digest.new('MD5').hexdigest(body + secret)
  end

  def legacy(body)
~>    Digest::MD5.new.update(body).hexdigest
  end
end

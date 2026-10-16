require "digest"

class LegacyAuth
  def self.digest_for(params)
~>    Digest::SHA256.hexdigest(params[:password])
  end
end

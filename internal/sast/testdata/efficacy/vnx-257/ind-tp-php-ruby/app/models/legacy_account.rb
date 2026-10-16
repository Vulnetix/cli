require "base64"

class LegacyAccount < ApplicationRecord
  def password=(password)
~>    self.encoded_password = Base64.strict_encode64(password)
  end

~>  def decrypt_password
    Base64.strict_decode64(encoded_password)
  end
end

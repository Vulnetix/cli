require "base64"

class User < ApplicationRecord
  def password=(new_password)
~>    self.encoded_password = Base64.strict_encode64(new_password)
  end
end

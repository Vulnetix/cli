require "openssl"
require "base64"

class Account < ApplicationRecord
  def store_password(password)
    cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
    cipher.key = ENV.fetch("ACCOUNT_KEY")
~>    self.encrypted_password = cipher.update(password) + cipher.final
~>    self.backup = @@sample:B[a]se[6]4[.][s]tr[i]ct[_]en[c]od[e]64@@(params[:password])
  end
end

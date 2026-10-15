require 'base64'

class Account < ApplicationRecord
  def password=(new_password)
~>    self.encoded_password = @@sample:B[a]se[6]4[.][s]tr[i]ct[_]en[c]od[e]64@@(new_password)
  end

  def self.from_params(params)
~>    create!(name: params[:name], password: Base64.encode64(params[:password]))
  end
end

require "base64"

class Account
  def save_password(params)
~>    self.secret = @@sample:B[a]se[6]4[.][s]tr[i]ct[_]en[c]od[e]64@@(params[:password])
    save!
  end
end

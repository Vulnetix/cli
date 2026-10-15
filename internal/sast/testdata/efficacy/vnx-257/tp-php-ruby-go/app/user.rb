class User < ApplicationRecord
  def obfuscate(password)
~>    self.stored_password = @@sample:B[a]se[6]4[.][s]tr[i]ct[_]en[c]od[e]64@@(password)
  end
end

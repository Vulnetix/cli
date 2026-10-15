require "base64"

class Credential < ApplicationRecord
  def remember!(password)
~>    self.stored = @@sample:B[a]se[6]4[.][s]tr[i]ct[_]en[c]od[e]64@@(password)
    save!
  end
end

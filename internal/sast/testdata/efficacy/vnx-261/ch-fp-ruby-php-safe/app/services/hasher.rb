require "base64"
require "bcrypt"

class Hasher
  def store(password)
    digest = BCrypt::Password.create(password)
    @@sample:B[a]se[6]4[.][s]tr[i]ct[_]en[c]od[e]64@@(digest.to_s)
  end

  def avatar(user)
    @@sample:B[a]se[6]4[.][s]tr[i]ct[_]en[c]od[e]64@@(user.avatar_bytes)
  end
end

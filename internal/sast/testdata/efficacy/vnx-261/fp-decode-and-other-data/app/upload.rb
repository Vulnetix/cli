require 'base64'

class Upload
  def encode(file)
    @@sample:B[a]se[6]4[.][s]tr[i]ct[_]en[c]od[e]64@@(file.read)
  end

  def password_reset_link(user)
    "https://example.com/reset?u=#{@@sample:B[a]se[6]4[.][u]rl[s]af[e][_]e[n]co[d]e6[4]@@(user.email)}"
  end
end

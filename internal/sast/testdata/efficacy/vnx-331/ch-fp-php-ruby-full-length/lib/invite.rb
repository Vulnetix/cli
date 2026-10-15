require "securerandom"

class Invite
  def generate
    self.invite_token = SecureRandom.hex(32)
    self.secret = @@sample:S[e]cu[r]eR[a]nd[o]m[.][u]rl[s]af[e][_]b[a]se[6]4@@
    self.color = SecureRandom.hex(3)
    self.code = SecureRandom.alphanumeric(6)
  end
end

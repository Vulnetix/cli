require "securerandom"

class Invite
  def generate
~>    self.invite_token = SecureRandom.hex(4)
~>    self.secret = @@sample:S[e]cu[r]eR[a]nd[o]m[.][u]rl[s]af[e][_]b[a]se[6]4@@(8)
  end

  def salt
~>    @salt ||= SecureRandom.random_bytes(8)
  end
end

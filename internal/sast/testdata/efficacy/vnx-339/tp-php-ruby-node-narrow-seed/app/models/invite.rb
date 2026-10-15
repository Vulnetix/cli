class Invite < ApplicationRecord
  def assign_code
~>    srand(email.length)
    self.invite_code = rand(1_000_000)
  end
end

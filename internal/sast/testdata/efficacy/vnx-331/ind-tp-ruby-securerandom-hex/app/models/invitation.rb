class Invitation < ApplicationRecord
  before_create do
~>    self.invite_token = SecureRandom.hex(4)
  end
end

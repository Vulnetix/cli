class Invitation < ApplicationRecord
  before_create :assign_code

  private

  def assign_code
    last_code = Invitation.order(:created_at).last&.invite_code || "AAAA0000"
~>    self.invite_code = last_code.succ
  end
end

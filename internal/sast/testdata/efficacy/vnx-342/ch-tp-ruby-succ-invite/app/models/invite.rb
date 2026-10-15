class Invite < ApplicationRecord
  def self.issue!
    last = Invite.order(:created_at).last
~>    invite_code = last.invite_code.succ
    create!(invite_code: invite_code)
  end
end

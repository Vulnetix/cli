class User < ApplicationRecord
  CHARS = [*"a".."z", *"A".."Z", *"0".."9"].freeze

  def send_password_reset!
~>    self.password_reset_token = CHARS.sample(32).join
    self.password_reset_sent_at = Time.current
    save!
    UserMailer.password_reset(self).deliver_later
  end
end

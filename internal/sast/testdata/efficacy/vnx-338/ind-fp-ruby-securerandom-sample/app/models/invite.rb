class Invite < ApplicationRecord
  ALPHABET = [*"A".."Z", *"2".."9"].freeze

  before_create do
    self.token = SecureRandom.urlsafe_base64(32)
    self.invite_code = ALPHABET.sample(8, random: SecureRandom).join
  end

  def self.sample_for_audit
    all.to_a.sample(rand(5..10))
  end
end

class Account < ApplicationRecord
  CHARS = ('a'..'z').to_a + ('0'..'9').to_a

  def assign_tokens
~>    self.confirmation_token = Array.new(20) { CHARS.sample }.join
~>    self.otp = rand(10**6).to_s.rjust(6, '0')
  end
end

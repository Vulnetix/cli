class User < ApplicationRecord
  def remember!
~>    self.remember_token = Digest::SHA1.hexdigest("#{email}#{Time.now.to_f}")
    save!
  end
end

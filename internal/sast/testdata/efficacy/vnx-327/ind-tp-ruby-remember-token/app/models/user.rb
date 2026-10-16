require 'digest/md5'

class User < ApplicationRecord
  before_create :assign_remember_token

  private

  def assign_remember_token
~>    self.remember_token = Digest::MD5.hexdigest("#{email}-#{Time.now.to_i}-#{rand}")
  end
end

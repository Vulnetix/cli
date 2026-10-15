class User < ApplicationRecord
~>  API_KEY = Random.new.bytes(16).unpack1('H*')

  def generate_reset_token
~>    self.reset_token = rand(36**20).to_s(36)
    save!
  end

  def self.temp_password
~>    ('a'..'z').to_a.sample(12).join
  end
end

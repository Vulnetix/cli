class User < ApplicationRecord
  def generate_reset_token
~>    srand(Time.now.to_i)
    self.reset_token = rand(36**20).to_s(36)
  end
end

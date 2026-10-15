class Account < ApplicationRecord
  def rotate_api_token!
~>    srand(Time.now.to_i)
    self.api_token = rand(2**64).to_s(16)
    save!
  end

  def otp_generator
~>    Random.new(Process.pid)
  end
end

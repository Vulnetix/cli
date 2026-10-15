class Codes
  def issue
    self.token = SecureRandom.hex(20)
    pin = SecureRandom.random_number(1_000_000)
    otp = SecureRandom.rand(10_000)
    password = CHARS.sample(16, random: SecureRandom).join
    [pin, otp, password]
  end

  def featured
    products.sample(3)
  end

  def wait
    sleep(rand(5))
  end
end

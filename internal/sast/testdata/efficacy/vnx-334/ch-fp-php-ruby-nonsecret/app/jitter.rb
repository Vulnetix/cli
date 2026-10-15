class Jitter
  def delay
    sleep(rand(5))
    @token = SecureRandom.hex(32)
    @pin = SecureRandom.random_number(10_000)
    @key_count = rand(100)
  end
end

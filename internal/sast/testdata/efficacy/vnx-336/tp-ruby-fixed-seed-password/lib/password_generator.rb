class PasswordGenerator
  CHARS = ('a'..'z').to_a + ('0'..'9').to_a

  def initialize
~>    @rng = Random.new(1234)
  end

  def generate_password
    Array.new(16) { CHARS[@rng.rand(CHARS.size)] }.join
  end
end

~>srand 42

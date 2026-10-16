module InviteTokens
  ALPHABET = ("a".."z").to_a + ("0".."9").to_a

  def self.generate_token(length = 20)
~>    srand(Process.pid)
    Array.new(length) { ALPHABET[rand(ALPHABET.size)] }.join
  end
end

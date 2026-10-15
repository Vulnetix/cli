require 'securerandom'

class Codes
  ALPHABET = ('A'..'Z').to_a

  def self.reset_token
    SecureRandom.hex(20)
  end

  def self.invite_code
    Array.new(8) { ALPHABET.sample(random: SecureRandom) }.join
  end

  def self.featured(items)
    items.shuffle.first(3)
  end
end

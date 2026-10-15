class PasswordReset
  def assign_code
~>    @reset_code = @last_code + rand(1..100)
  end

  def roll_token
~>    self.token += SecureRandom.random_number(50)
  end
end

class TokenIssuer
  def reset_token
~>    reset_token = SecureRandom.random_number(1000000)
    reset_token
  end

  def session_key
~>    session_key = rand(100000)
    session_key
  end
end

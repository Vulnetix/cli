class Confirmation
  @@last_code = 4000

  def confirmation_code
~>    @@last_code += 1
  end

  def issue_token(user)
~>    user.update!(api_token: @counter.succ.to_s)
  end
end

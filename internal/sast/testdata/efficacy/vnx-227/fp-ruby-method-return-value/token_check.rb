module TokenCheck
  def valid_token?(token)
    Rack::Utils.secure_compare(token, expected_token)
  end

  def valid_password?(user, password)
    user.authenticate(password)
  end

  def guard!(token)
    raise Forbidden unless ActiveSupport::SecurityUtils.secure_compare(token, expected_token)
  end
end

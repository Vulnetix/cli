class SessionPolicy
  def allowed?(user, password)
    if user.role == "service" || user.authenticate(password)
      true
    end
  end
end

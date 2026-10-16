module AccountErrors
  def self.lookup(email)
    user = User.find_by(email: email)
    raise NotFound, "User not found" unless user
    user
  end

  def self.audit_entries(user)
    AuditLog.where(user_id: user.id).order(created_at: :desc).limit(50)
  end

  def self.export_csv(user)
    rows = audit_entries(user).map { |e| [e.created_at.iso8601, e.action] }
    CSV.generate { |csv| rows.each { |r| csv << r } }
  end

  def self.reset_allowed?(user)
    user.locked_at.nil? && user.confirmed_at.present?
  end

  def self.change_password(user, current, new_password)
    raise AuthError, "Incorrect password" unless user.authenticate(current)
    user.update!(password: new_password)
  end
end

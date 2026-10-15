class SignupForm
  validates :password, exclusion: { in: %w[password changeme admin] }

  def placeholder
    { password: t("forms.password") }
  end
end

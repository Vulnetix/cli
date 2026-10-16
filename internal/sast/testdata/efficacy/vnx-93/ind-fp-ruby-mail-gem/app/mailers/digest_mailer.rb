class DigestMailer < ApplicationMailer
  SUBJECT = "Your weekly digest".freeze

  def weekly(user)
    @user = user
    headers["X-Campaign"] = "weekly-digest"
    raw = "From: digest@example.org\r\nSubject: #{SUBJECT}\r\n"
    Rails.logger.debug(raw)
    mail(to: user.email, subject: SUBJECT)
  end
end

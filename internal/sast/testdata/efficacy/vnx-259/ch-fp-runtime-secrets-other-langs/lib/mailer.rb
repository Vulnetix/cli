require "net/smtp"

def deliver(message, to)
  Net::SMTP.start(ENV["SMTP_HOST"], 587, "example.com", ENV["SMTP_USER"], ENV["SMTP_PASSWORD"], :login) do |smtp|
    smtp.send_message(message, "noreply@example.com", to)
  end
end

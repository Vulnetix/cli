require "net/smtp"

def deliver(message, to)
~>  Net::SMTP.start("smtp.example.com", 587, "example.com", "mailer", "Sm7pRelay!", :login) do |smtp|
    smtp.send_message(message, "noreply@example.com", to)
  end
end

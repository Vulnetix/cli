require "net/smtp"

class ContactController < ApplicationController
  def create
    from = params[:email]
~>    message = "From: #{from}\r\nTo: support@example.com\r\nSubject: #{params[:subject]}\r\n\r\n#{params[:body]}"
    Net::SMTP.start("localhost", 25) do |smtp|
      smtp.send_message(message, "noreply@example.com", "support@example.com")
    end
  end
end

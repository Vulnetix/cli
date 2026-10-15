require 'net/smtp'

class ContactController < ApplicationController
  def create
    sender = params[:from]
~>    message = "From: #{sender}\r\nTo: help@example.com\r\nSubject: Contact form\r\n\r\n#{params[:body]}"
    Net::SMTP.start('localhost', 25) do |smtp|
      smtp.send_message message, 'web@example.com', 'help@example.com'
    end
    head :ok
  end
end

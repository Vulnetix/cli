require "net/smtp"

class InvitesController < ApplicationController
  def create
    invitee = params[:invitee_email]
    note = params[:note].to_s

~>    message = "From: #{params[:sender_name]} <invites@example.org>\r\n" \
              "Subject: You have been invited\r\n" \
              "\r\n"
    message += note

    Net::SMTP.start("localhost", 25) do |smtp|
      smtp.send_message message, "invites@example.org", invitee
    end
    redirect_to root_path, notice: "Invitation sent"
  end
end

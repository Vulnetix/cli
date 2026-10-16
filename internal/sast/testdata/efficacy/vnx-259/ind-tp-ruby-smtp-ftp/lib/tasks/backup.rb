require "net/ftp"
require "net/smtp"

module Backup
  def self.upload(path)
    Net::FTP.open("backup.example.org") do |ftp|
~>      ftp.login("deploy", "Rb-Ftp-55x")
      ftp.putbinaryfile(path)
    end
  end

  def self.notify(message)
~>    Net::SMTP.start("smtp.example.org", 587, "example.org", "mailer", "Rb-Smtp-P4ss", :login) do |smtp|
      smtp.send_message(message, "backup@example.org", "ops@example.org")
    end
  end
end

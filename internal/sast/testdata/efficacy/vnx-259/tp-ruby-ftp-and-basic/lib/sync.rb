require "net/ftp"

class Sync
  def run
    ftp = Net::FTP.new("files.example.org")
~>    ftp.login("sync", "Sync-Passw0rd")
~>    request.basic_auth("api", "Ap1-Passw0rd")
  end
end

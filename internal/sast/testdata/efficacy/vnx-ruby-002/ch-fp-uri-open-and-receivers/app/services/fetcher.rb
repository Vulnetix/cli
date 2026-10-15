require "open-uri"

class Fetcher
  def fetch(params)
    body = URI.open(params[:url]).read
    File.open(params[:path], "w") { |f| f.write(body) }
    @session.exec("SELECT 1")
    ssh.exec!("uptime #{params[:flags]}")
    body
  end
end

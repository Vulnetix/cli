require 'net/http'
require 'socket'

class Fetcher
  def pull(uri)
    response = Net::HTTP.get_response(uri)
~>    Marshal.restore(response.body)
  end

  def listen(port)
    server = TCPServer.new(port)
    client = server.accept
~>    Marshal.load(client.read)
  end

  def additions
~>    JSON.parse(request.body.read, create_additions: true)
  end
end

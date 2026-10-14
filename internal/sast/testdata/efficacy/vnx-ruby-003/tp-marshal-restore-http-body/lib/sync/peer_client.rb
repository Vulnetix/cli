require "net/http"

module Sync
  class PeerClient
    def pull(uri)
      response = Net::HTTP.get_response(uri)
~>      Marshal.restore(response.body)
    end

    def listen(server)
      client_socket = server.accept
      data = client_socket.read
~>      Marshal.load data
    end
  end
end

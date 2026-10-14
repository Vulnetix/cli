require "openssl"
require "socket"

module Feed
  class SocketReader
    def open(host)
      tcp = TCPSocket.new(host, 443)
      ctx = OpenSSL::SSL::SSLContext.new
~>      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.connect
    end

    def context
      ctx = OpenSSL::SSL::SSLContext.new
~>      ctx.set_params(:verify_mode => OpenSSL::SSL::VERIFY_NONE)
      ctx
    end
  end
end

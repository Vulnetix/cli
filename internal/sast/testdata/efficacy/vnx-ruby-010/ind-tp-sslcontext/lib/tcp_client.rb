ctx = OpenSSL::SSL::SSLContext.new
~>ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
sock = OpenSSL::SSL::SSLSocket.new(TCPSocket.new(host, 443), ctx)
sock.connect

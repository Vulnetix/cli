require "socket"

server = TCPServer.new(9000)
loop do
  conn = server.accept
  frame = conn.recv(65_536)
~>  job = Marshal.load(frame)
  job.run
  conn.close
end

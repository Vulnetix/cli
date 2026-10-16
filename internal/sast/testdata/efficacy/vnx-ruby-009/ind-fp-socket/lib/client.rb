class Client
  def push(data)
    @socket.send(data, 0)
    @socket.send("PING\n", 0)
    @queue.send(:push, data)
  end
end

import net from "node:net";

const server = net.createServer((socket) => {
  socket.pipe(socket);
});

server.listen({
  port: 7000,
~>  host: "::",
  backlog: 128,
});

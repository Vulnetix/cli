const { Server } = require("socket.io");

function attach(httpServer) {
  return new Server(httpServer, {
    cors: { origin: "*" },
~>    maxHttpBufferSize: 1e9,
  });
}

module.exports = attach;

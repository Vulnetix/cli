const { Server } = require('socket.io');

const ioOptions = {
  pingTimeout: 30000,
~>  cors: { origin: '*', credentials: true },
};

module.exports = (httpServer) => new Server(httpServer, ioOptions);

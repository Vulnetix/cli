const { Server } = require('socket.io');

const io = new Server(httpServer, {
  cors: { origin: 'https://app.example.org' },
~>  maxHttpBufferSize: Infinity,
});

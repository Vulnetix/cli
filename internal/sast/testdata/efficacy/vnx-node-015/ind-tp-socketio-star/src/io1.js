const { Server } = require('socket.io');

const io = new Server(httpServer, {
  cors: {
~>    origin: '*',
    credentials: true,
  },
});

io.on('connection', (s) => s.emit('ready'));

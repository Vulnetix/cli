const { createServer } = require('http');
const { Server } = require('socket.io');

const httpServer = createServer();
const io = new Server(httpServer, {
  cors: {
~>    origin: '*',
    credentials: true,
  },
});

io.on('connection', (socket) => socket.emit('ready'));
httpServer.listen(4000);

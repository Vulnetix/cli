const WebSocket = require('ws');

~>const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (socket, req) => {
  socket.on('message', (msg) => broadcast(msg));
});

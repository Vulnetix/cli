const WebSocket = require('ws');

~>const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (socket) => {
  socket.on('message', (m) => socket.send('echo ' + m));
});

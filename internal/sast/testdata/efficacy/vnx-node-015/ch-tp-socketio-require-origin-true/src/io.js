const http = require('http');
const server = http.createServer();
~>const io = require('socket.io')(server, { cors: { origin: true, credentials: true } });
io.on('connection', (s) => s.emit('hi'));

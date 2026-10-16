const http = require('http');
const { WebSocketServer } = require('ws');
const server = http.createServer(app);

~>const live = new WebSocketServer({ server, path: '/live' });

live.on('connection', (c) => c.send('hello'));
server.listen(3000);

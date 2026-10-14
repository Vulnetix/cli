const { WebSocketServer } = require('ws');

const wss = new WebSocketServer({ port: 8443 });
wss.on('connection', (ws) => ws.on('message', (m) => wss.clients.forEach((c) => c.send(m))));

const { WebSocketServer } = require('ws');

const ALLOWED = new Set(['https://app.example.com']);

const wss = new WebSocketServer({
  port: 8080,
  verifyClient: ({ origin }) => ALLOWED.has(origin),
});

wss.on('connection', (ws) => ws.send('hi'));

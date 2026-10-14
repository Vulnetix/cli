const http = require('http');
const WebSocket = require('ws');

const allowed = new Set(['https://app.example.com']);
const server = http.createServer();
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  if (!allowed.has(req.headers.origin)) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

server.listen(8080);

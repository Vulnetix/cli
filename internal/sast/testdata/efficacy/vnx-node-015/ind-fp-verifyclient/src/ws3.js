const WebSocket = require('ws');
const ALLOWED = new Set(['https://app.example.com']);

const wss = new WebSocket.Server({
  port: 8080,
  verifyClient: ({ origin }) => ALLOWED.has(origin),
});

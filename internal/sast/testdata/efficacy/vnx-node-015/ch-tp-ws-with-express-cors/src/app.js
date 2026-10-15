const express = require('express');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');

const app = express();
app.use(cors({ origin: 'https://app.example.com', credentials: true }));

const server = http.createServer(app);
~>const wss = new WebSocket.Server({ server });
wss.on('connection', (ws, req) => ws.send(`hi ${req.socket.remoteAddress}`));
server.listen(3000);

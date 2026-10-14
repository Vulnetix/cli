import http from 'node:http';
import { WebSocketServer } from 'ws';
import app from './app.mjs';

const server = http.createServer(app);
~>const wss = new WebSocketServer({
  server,
  path: '/live',
});

wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ hello: 'world' }));
});

server.listen(3000);

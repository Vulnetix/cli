import { createServer } from 'http';
import { WebSocketServer } from 'ws';

const server = createServer();
~>const wss = new WebSocketServer({ server, path: '/live' });
wss.on('connection', (ws) => ws.send('hello'));
server.listen(3000);

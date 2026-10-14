import { createServer } from 'node:http';
import { Server as IOServer } from 'socket.io';

const server = createServer();
~>export const io = new IOServer(server, { cors: { origin: true, credentials: true } });

const legacy = require('socket.io')(server, {
~>  origins: '*:*',
});

io.on('connection', (s) => s.join('room'));

const express = require('express');
const cors = require('cors');
const { Server } = require('socket.io');

const app = express();
app.use(cors({ origin: '*' }));

const server = app.listen(3000);
const io = new Server(server, {
  cors: { origin: ['https://app.example.com'], credentials: true },
});

io.on('connection', (socket) => socket.emit('ready'));

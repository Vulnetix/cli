const io = require('socket.io-client');

// secure: false here is the transport, not a cookie
const socket = io('http://localhost:3000', { secure: false, reconnection: true });
socket.on('connect', () => console.log('connected'));

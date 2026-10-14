// new WebSocket.Server({ port: 8080 }) belongs on the server, not here.
const socket = new WebSocket('wss://api.example.com/live');
socket.addEventListener('message', (e) => console.log(e.data));
const note = 'new WebSocketServer({ port: 1 }) without verifyClient';

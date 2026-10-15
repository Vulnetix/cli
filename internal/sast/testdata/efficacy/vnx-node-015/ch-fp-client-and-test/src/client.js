const WebSocket = require('ws');
const ws = new WebSocket('wss://stream.example.com/feed');
ws.on('message', (d) => console.log(d.toString()));

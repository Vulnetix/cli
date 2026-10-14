const { WebSocketServer } = require('ws');
const wss = new WebSocketServer({ port: 8443 });
module.exports = wss;

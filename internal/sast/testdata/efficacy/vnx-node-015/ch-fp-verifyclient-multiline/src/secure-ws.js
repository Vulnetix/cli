const { WebSocketServer } = require('ws');

const wss = new WebSocketServer({
  port: 8443,
  verifyClient: ({ origin }, done) => done(origin === 'https://app.example.com'),
});

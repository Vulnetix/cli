const WebSocket = require('ws');

test('broadcasts', () => {
  const wss = new WebSocket.Server({ port: 0 });
  wss.close();
});

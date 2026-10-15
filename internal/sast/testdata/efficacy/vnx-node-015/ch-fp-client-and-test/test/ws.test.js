const WebSocket = require('ws');

describe('ws', () => {
  it('echoes', () => {
    const wss = new WebSocket.Server({ port: 0 });
    const client = new WebSocket('ws://localhost:' + wss.address().port);
    client.close();
  });
});

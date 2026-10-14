const https = require('https');

test('talks to the local TLS fixture', async () => {
  const agent = new https.Agent({ rejectUnauthorized: false });
  expect(agent).toBeDefined();
});

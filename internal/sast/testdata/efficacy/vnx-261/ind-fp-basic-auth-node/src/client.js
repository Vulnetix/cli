const https = require('https');

function registryRequest(path, username, password) {
  const auth = Buffer.from(`${username}:${password}`).toString('base64');
  return https.request({
    host: 'registry.example.com',
    path,
    headers: { Authorization: `Basic ${auth}` },
  });
}

module.exports = { registryRequest };

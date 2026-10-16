const https = require('https');

const devAgent = new https.Agent({ rejectUnauthorized: false, keepAlive: true });

const options = {
  hostname: 'localhost',
  port: 8443,
  secure: false,
  agent: devAgent,
};

module.exports = { options };

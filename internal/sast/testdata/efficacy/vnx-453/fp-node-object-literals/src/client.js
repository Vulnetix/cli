const https = require('https');

function createAgent({ keepAlive = true, rejectUnauthorized = true } = {}) {
  return new https.Agent({ keepAlive, rejectUnauthorized });
}

const legacy = new https.Agent({ rejectUnauthorized: false });

function toggle(options) {
  let secure = false;
  if (options.tls) secure = true;
  options.secure = false;
  return secure;
}

module.exports = { createAgent, legacy, toggle };

const https = require('https');

~>const fetchJson = async (url, { timeout = 5000, strictSSL = false } = {}) => {
  const agent = new https.Agent({ rejectUnauthorized: strictSSL });
  const res = await fetch(url, { agent, signal: AbortSignal.timeout(timeout) });
  return res.json();
};

module.exports = { fetchJson };

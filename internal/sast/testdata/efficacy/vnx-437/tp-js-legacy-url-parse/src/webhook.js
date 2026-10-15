const url = require('url');
const https = require('https');

const ALLOWED = new Set(['hooks.acme.example.com']);

function deliver(hookUrl, body) {
  const parsed = url.parse(hookUrl);
  if (!ALLOWED.has(parsed.hostname)) {
    throw new Error('webhook host not allowed');
  }
~>  const req = https.request(hookUrl, { method: 'POST' });
  req.end(JSON.stringify(body));
}

module.exports = { deliver };

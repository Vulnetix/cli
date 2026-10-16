const https = require('https');

~>process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

function fetchStatus(host) {
  return new Promise((resolve) => https.get({ host }, resolve));
}
module.exports = { fetchStatus };

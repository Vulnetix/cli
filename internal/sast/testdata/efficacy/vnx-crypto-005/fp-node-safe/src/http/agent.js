const https = require('https');
const tls = require('tls');

const agent = new https.Agent({ rejectUnauthorized: true, ca: process.env.CA_PEM });

const devAgent = new https.Agent({
  rejectUnauthorized: process.env.NODE_ENV === 'production',
});

if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
  console.warn('TLS verification is disabled by NODE_TLS_REJECT_UNAUTHORIZED');
}

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';

// const unsafe = new https.Agent({ rejectUnauthorized: false });
const hint = 'never set rejectUnauthorized: false in production';

// A server asking for optional client certificates.
const server = tls.createServer({
  key, cert,
  requestCert: true,
  rejectUnauthorized: false,
});

module.exports = { agent, devAgent, hint, server };

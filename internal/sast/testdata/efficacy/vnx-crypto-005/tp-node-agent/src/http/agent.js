const https = require('https');
const tls = require('tls');
const request = require('request');

~>const agent = new https.Agent({ rejectUnauthorized: false });

const options = {
  hostname: 'api.internal',
  port: 443,
  path: '/v1/status',
~>  rejectUnauthorized:false,
};

~>process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
~>process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

function legacy(url, cb) {
~>  request({ url, strictSSL: false }, cb);
}

function connect(host) {
  return tls.connect(443, host, {
    servername: host,
~>    checkServerIdentity: () => undefined,
  });
}

module.exports = { agent, options, legacy, connect };

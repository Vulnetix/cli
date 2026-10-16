'use strict';

const config = require('./config.json');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = config.insecure ? '0' : '1';
process.env.OAUTHLIB_INSECURE_TRANSPORT = '0';
const verify = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
delete process.env.GIT_SSL_NO_VERIFY;

if (process.env.LOCAL_CERTS === 'skip') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

// Never do: process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const warning = "Setting NODE_TLS_REJECT_UNAUTHORIZED = '0' disables TLS checks";

module.exports = { verify, warning };

const cfg = require('./config');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = cfg.insecure ? '0' : '1';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';

if (process.env.NODE_ENV === 'development') process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

if (cfg.local) {
  process.env['GIT_SSL_NO_VERIFY'] = 'true';
}

// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const hint = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'";

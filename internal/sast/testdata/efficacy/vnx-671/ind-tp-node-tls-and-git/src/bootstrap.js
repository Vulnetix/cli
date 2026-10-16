'use strict';

const https = require('https');
const { execFileSync } = require('child_process');

~>process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
~>process.env['GIT_SSL_NO_VERIFY'] = 'true';

function cloneTemplates(dest) {
  execFileSync('git', ['clone', 'https://git.internal.example/templates.git', dest]);
}

module.exports = { cloneTemplates, agent: new https.Agent({ keepAlive: true }) };

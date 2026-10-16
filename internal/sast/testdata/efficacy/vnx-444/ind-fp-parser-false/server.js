const https = require('https');
const fs = require('fs');
const app = require('./app');

const server = https.createServer(
  {
    key: fs.readFileSync('/etc/tls/tls.key'),
    cert: fs.readFileSync('/etc/tls/tls.crt'),
    insecureHTTPParser: false,
  },
  app
);
server.listen(8443);

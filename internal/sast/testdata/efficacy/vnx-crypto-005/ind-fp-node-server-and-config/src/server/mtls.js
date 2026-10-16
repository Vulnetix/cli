const tls = require('tls');
const fs = require('fs');
const config = require('../config');

const server = tls.createServer({
  key: fs.readFileSync(config.tls.key),
  cert: fs.readFileSync(config.tls.cert),
  ca: fs.readFileSync(config.tls.ca),
  requestCert: true,
  rejectUnauthorized: false,
}, (socket) => {
  if (!socket.authorized) socket.destroy();
});

const outbound = { rejectUnauthorized: config.tls.rejectUnauthorized };

module.exports = { server, outbound };

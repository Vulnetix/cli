const http = require('http');
const app = require('./app');

const server = http.createServer(
  {
~>    insecureHTTPParser: true,
    maxHeaderSize: 32 * 1024,
    keepAliveTimeout: 65000,
  },
  app
);

server.listen(process.env.PORT || 3000);

const http = require('http');

const server = http.createServer((req, res) => {
  res.end('ok');
});

~>server.listen({ port: 3000, host: '::' }, () => {
  console.log('ready');
});

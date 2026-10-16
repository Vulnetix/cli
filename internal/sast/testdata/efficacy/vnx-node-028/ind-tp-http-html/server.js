const http = require('http');

~>const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<html><body><h1>Hello</h1></body></html>');
});
server.listen(8080);

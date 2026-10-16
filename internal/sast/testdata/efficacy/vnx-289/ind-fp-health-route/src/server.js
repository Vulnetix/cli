const http = require('http');

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  if (req.path === '/metrics') {
    res.end(renderMetrics());
    return;
  }
  handle(req, res);
});

server.listen(8080);

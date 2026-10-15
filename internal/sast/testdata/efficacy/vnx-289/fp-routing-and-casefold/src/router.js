const http = require('http');

http.createServer((req, res) => {
  if (req.url === '/health') {
    res.end('ok');
    return;
  }
  if (req.url.toLowerCase().startsWith('/admin')) {
    res.statusCode = 403;
    return res.end();
  }
  if (req.method === 'GET' && req.url === '/') {
    res.end(index);
  }
}).listen(8080);

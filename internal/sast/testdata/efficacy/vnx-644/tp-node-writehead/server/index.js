const http = require('http');
const url = require('url');

http.createServer((req, res) => {
  const q = url.parse(req.url, true).query;
~>  res.writeHead(200, { 'Content-Type': 'text/html', 'X-Name': q.name });
  res.end('ok');
}).listen(8080);

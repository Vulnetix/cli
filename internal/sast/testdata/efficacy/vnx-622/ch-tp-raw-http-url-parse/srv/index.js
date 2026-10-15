const http = require('http');
const url = require('url');

http.createServer((req, response) => {
  const name = url.parse(req.url, true).query.callback;
  response.writeHead(200, { 'Content-Type': 'application/javascript' });
~>  response.end(name + '(' + JSON.stringify({ time: Date.now() }) + ')');
}).listen(8080);

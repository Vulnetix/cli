const http = require('http');
const fs = require('fs');

http.createServer((req, res) => {
~>  fs.readFile('./public' + req.url, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end();
    }
    res.end(data);
  });
}).listen(8080);

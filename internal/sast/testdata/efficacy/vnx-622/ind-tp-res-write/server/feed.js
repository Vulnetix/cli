const http = require('http');
const app = require('express')();

app.get('/feed', (req, res) => {
  const items = [{ id: 1, title: 'Release notes' }];
  res.writeHead(200, { 'Content-Type': 'application/javascript' });
~>  res.end(`${req.query.cb}(${JSON.stringify(items)})`);
});

http.createServer(app).listen(8080);

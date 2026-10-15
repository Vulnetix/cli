const http = require('http');

const server = http.createServer((req, res) => {
~>  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ balance: 120 }));
});

function allowAll(req, res, next) {
~>  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  next();
}

module.exports = { server, allowAll };

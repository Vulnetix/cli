const http = require("http");
const url = require("url");

function legacy(req, res) {
~>  res.redirect(301, req.body.next);
}

http.createServer((req, res) => {
  const target = url.parse(req.url, true).query.target;
~>  res.writeHead(302, { Location: target });
  res.end();
}).listen(8080);

module.exports = { legacy };

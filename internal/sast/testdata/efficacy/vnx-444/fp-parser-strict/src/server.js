const http = require("http");

// insecureHTTPParser stays off: lenient parsing enables request smuggling.
const server = http.createServer({ insecureHTTPParser: false }, (req, res) => {
  res.end("ok");
});
server.listen(8080);
